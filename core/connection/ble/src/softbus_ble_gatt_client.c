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
#include <stdio.h>

#include "cJSON.h"
#include "common_list.h"
#include "message_handler.h"
#include "securec.h"
#include "softbus_adapter_ble_gatt_client.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
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

#define INVALID_GATTC_ID (-1)
#define DEFAULT_MTU_SIZE 512
#define BLE_GATTC_INFO "BleGattcInfo"
#define CLIENT_CONNECTED_WAIT_TIME (5*1000)
#define CLIENT_SERVICE_SEARCHED_WAIT_TIME (5*1000)
#define CLIENT_NOTIFICATED_ONCE_WAIT_TIME (3*1000)
#define CLIENT_NOTIFICATED_TWICE_WAIT_TIME (3*1000)
#define CLIENT_MTU_SETTED_WAIT_TIME (3*1000)
#define CLIENT_HANDSHAKE_WAIT_TIME (5*1000)

typedef enum {
    BLE_GATT_CLIENT_INITIAL = 0,
    BLE_GATT_CLIENT_STARTING,
    BLE_GATT_CLIENT_STARTED,
    BLE_GATT_CLIENT_SERVICE_SEARCHING,
    BLE_GATT_CLIENT_SERVICE_SEARCHED,
    BLE_GATT_CLIENT_NOTIFICATING_ONCE,
    BLE_GATT_CLIENT_NOTIFICATED_ONCE,
    BLE_GATT_CLIENT_NOTIFICATING_TWICE,
    BLE_GATT_CLIENT_NOTIFICATED_TWICE,
    BLE_GATT_CLIENT_MTU_SETTING,
    BLE_GATT_CLIENT_MTU_SETTED,
    BLE_GATT_CLIENT_CONNECTED,
    BLE_GATT_CLIENT_STOPPING,
    BLE_GATT_CLIENT_STOPPED,
    BLE_GATT_CLIENT_INVALID
} GattClientState;

typedef enum {
    CLIENT_CONNECTED,
    CLIENT_SERVICE_SEARCHED,
    CLIENT_NOTIFICATED,
    CLIENT_DISCONNECTED,
    CLIENT_MTU_SETTED,
    CLIENT_TIME_OUT,
} BleClientConnLoopMsg;

static SoftBusHandler g_bleClientAsyncHandler = {
    .name ="g_bleClientAsyncHandler"
};

typedef struct {
    ListNode node;
    int32_t clientId;
    int32_t state;
    SoftBusBtAddr peerAddr;
} BleGattcInfo;

typedef struct {
    int32_t errCode;
} BleCilentErrCode;

static SoftBusGattcCallback g_softbusGattcCb = {0};
static SoftBusBleConnCalback *g_softBusBleConnCb = NULL;
static SoftBusList *g_gattcInfoList = NULL;
static bool g_gattcIsInited = false;
static bool UpdateBleGattcInfoStateInner(BleGattcInfo *infoNode, int32_t newState);
static int32_t BleGattcDump(int fd);
static SoftBusMessage *BleClientConnCreateLoopMsg(int32_t what, uint64_t arg1, uint64_t arg2, const char *data);

static void FreeBleClientMessage(SoftBusMessage *msg)
{
    if (msg == NULL) {
        return;
    }
    if (msg->obj != NULL) {
        SoftBusFree(msg->obj);
        msg->obj = NULL;
    }
    SoftBusFree(msg);
}

static int32_t BleClientPostMsgDelay(int32_t msgWhat, int32_t clientId, int32_t errCode, int32_t time)
{
    BleCilentErrCode *bleErrCode = SoftBusCalloc(sizeof(BleCilentErrCode));
    if (bleErrCode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleClientPostMsgDelay SoftBusCalloc failed");
        return SOFTBUS_ERR;
    }
    bleErrCode->errCode = errCode;
    SoftBusMessage *msg = BleClientConnCreateLoopMsg(msgWhat, clientId, 0, (char *)bleErrCode);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "creat msg err, msg->what:%d", msgWhat);
        SoftBusFree(bleErrCode);
        bleErrCode = NULL;
        return SOFTBUS_ERR;
    }
    g_bleClientAsyncHandler.looper->PostMessageDelay(g_bleClientAsyncHandler.looper, msg, time);
    return SOFTBUS_OK;
}

static int32_t BleCilentRemoveMessageFunc(const SoftBusMessage *msg, void *args)
{
    if (msg == NULL || args == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleCilentRemoveMessageFunc invalid param");
        return SOFTBUS_ERR;
    }
    uint64_t clientId = (uint64_t)(uintptr_t)args;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "msg->arg1 = %lu, clientId = %lu", msg->arg1, clientId);
    if ((msg->what == CLIENT_TIME_OUT) && (msg->arg1 == clientId)) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

static BleGattcInfo *CreateNewBleGattcInfo(SoftBusBtAddr *bleAddr, int32_t clientId)
{
    BleGattcInfo *infoNode = (BleGattcInfo *)SoftBusCalloc(sizeof(BleGattcInfo));
    if (infoNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc infoNode failed");
        return NULL;
    }
    ListInit(&(infoNode->node));
    infoNode->clientId = clientId;
    infoNode->state = BLE_GATT_CLIENT_STARTING;
    if (memcpy_s(infoNode->peerAddr.addr, BT_ADDR_LEN, bleAddr->addr, BT_ADDR_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s fail");
        SoftBusFree(infoNode);
        return NULL;
    }
    return infoNode;
}

static BleGattcInfo *GetBleGattcInfoByClientIdInner(int32_t clientId)
{
    BleGattcInfo *infoNode = NULL;
    LIST_FOR_EACH_ENTRY(infoNode, &(g_gattcInfoList->list), BleGattcInfo, node) {
        if (clientId == infoNode->clientId) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "GetBleGattcInfoByClientId exist");
            return infoNode;
        }
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleGattcInfoByClientId not exist");
    return NULL;
}

static int32_t AddGattcInfoToList(BleGattcInfo *info)
{
    BleGattcInfo *infoNode = NULL;
    if (SoftBusMutexLock(&g_gattcInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(infoNode, &(g_gattcInfoList->list), BleGattcInfo, node) {
        if (memcmp(infoNode->peerAddr.addr, info->peerAddr.addr, BT_ADDR_LEN) != 0) {
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "peer bleaddr already existed");
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        return SOFTBUS_GATTC_DUPLICATE_PARAM;
    }
    ListTailInsert(&(g_gattcInfoList->list), &(info->node));
    g_gattcInfoList->cnt++;
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    return SOFTBUS_OK;
}

static int32_t RemoveGattcInfoFromList(int32_t clientId)
{
    if (SoftBusMutexLock(&g_gattcInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return SOFTBUS_LOCK_ERR;
    }
    BleGattcInfo *target = NULL;
    BleGattcInfo *iterator = NULL;
    LIST_FOR_EACH_ENTRY(iterator, &(g_gattcInfoList->list), BleGattcInfo, node) {
        if (iterator->clientId == clientId) {
            target = iterator;
            break;
        }
    }
    if (target != NULL) {
        g_gattcInfoList->cnt--;
        ListDelete(&(target->node));
        SoftBusFree(target);
    }
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    return SOFTBUS_OK;
}

static char *GetBleAttrUuid(int32_t module)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "GetBleAttrUuid %d", module);
    if (module == MODULE_BLE_NET) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleAttrUuid1");
        return SOFTBUS_CHARA_BLENET_UUID;
    } else if (module == MODULE_BLE_CONN) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleAttrUuid2");
        return SOFTBUS_CHARA_BLECONN_UUID;
    } else {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleAttrUuid3");
        return SOFTBUS_CHARA_BLECONN_UUID;
    }
}

int32_t SoftBusGattClientSend(const int32_t clientId, const char *data, int32_t len, int32_t module)
{
    if (g_gattcIsInited != true) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "gattc not init");
        return SOFTBUS_BLEGATTC_NONT_INIT;
    }
    if (clientId < 0 || data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_ERR;
    }

    SoftBusGattcData clientData;
    clientData.serviceUuid.uuid = SOFTBUS_SERVICE_UUID;
    clientData.serviceUuid.uuidLen = strlen(SOFTBUS_SERVICE_UUID);
    clientData.characterUuid.uuid = GetBleAttrUuid(module);
    clientData.characterUuid.uuidLen = strlen(SOFTBUS_SERVICE_UUID);
    clientData.valueLen = len;
    clientData.value = (char *)data;
    BleGattcInfo *infoNode = NULL;
    if (SoftBusMutexLock(&g_gattcInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return SOFTBUS_BLECONNECTION_MUTEX_LOCK_ERROR;
    }
    infoNode = GetBleGattcInfoByClientIdInner(clientId);
    if (infoNode == NULL) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleGattcInfoByClientIdInner not exist");
        return SOFTBUS_ERR;
    }
    if (infoNode->state != BLE_GATT_CLIENT_CONNECTED) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ble connect not ready, current state=%d", infoNode->state);
        return SOFTBUS_BLEGATTC_NOT_READY;
    }
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    return SoftbusGattcWriteCharacteristic(clientId, &clientData);
}

int32_t SoftBusGattClientConnect(SoftBusBtAddr *bleAddr, bool fastestConnectEnable)
{
    if (g_gattcIsInited != true) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "gattc not init");
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_NOT_INIT);
        return SOFTBUS_BLEGATTC_NONT_INIT;
    }
    if (bleAddr == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid ble addr param");
        return SOFTBUS_ERR;
    }
    int32_t clientId = SoftbusGattcRegister();
    if (clientId == INVALID_GATTC_ID) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "gattc rigister failed");
        return SOFTBUS_ERR;
    }
    BleGattcInfo *infoNode = CreateNewBleGattcInfo(bleAddr, clientId);
    if (infoNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "gattc create infoNode failed");
        (void)SoftbusGattcUnRegister(clientId);
        return SOFTBUS_ERR;
    }
    if (AddGattcInfoToList(infoNode) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "AddGattcInfoToList failed");
        (void)SoftbusGattcUnRegister(clientId);
        SoftBusFree(infoNode);
        return SOFTBUS_ERR;
    }
    if (fastestConnectEnable && SoftbusGattcSetFastestConn(infoNode->clientId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "enable ble fastest connection failed");
    }
    if (SoftbusGattcConnect(clientId, bleAddr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusGattcConnect failed");
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_CONNECT_FAIL);
        (void)SoftbusGattcUnRegister(clientId);
        (void)RemoveGattcInfoFromList(clientId);
        return SOFTBUS_ERR;
    }
    if (BleClientPostMsgDelay(CLIENT_TIME_OUT, clientId,
        SOFTBUS_BLECONNECTION_CLIENT_CONNECTED_TIMEOUT, CLIENT_CONNECTED_WAIT_TIME) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "post msg delay err");
        // continue anyway,
    }
    CLOGI("SoftBusGattClientConnect ok, clientId: %d, fastestEnable: %d", clientId, fastestConnectEnable);
    return clientId;
}

int32_t SoftBusGattClientDisconnect(int32_t clientId)
{
    if (g_gattcIsInited != true) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "gattc not init");
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_GATTCLIENT_INIT_FAIL);
        return SOFTBUS_BLEGATTC_NONT_INIT;
    }

    if (clientId < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_ERR;
    }
    BleGattcInfo *infoNode = NULL;
    if (SoftBusMutexLock(&g_gattcInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return SOFTBUS_LOCK_ERR;
    }
    infoNode = GetBleGattcInfoByClientIdInner(clientId);
    if (infoNode == NULL) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleGattcInfoByClientId not exist");
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_DISCONNECT_FAIL);
        return SOFTBUS_BLEGATTC_NODE_NOT_EXIST;
    }
    infoNode->state = BLE_GATT_CLIENT_STOPPING;
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SoftBusGattClientDisconnect");
    return SoftbusBleGattcDisconnect(clientId);
}

static bool UpdateBleGattcInfoStateInner(BleGattcInfo *infoNode, int32_t newState)
{
    if (newState == (infoNode->state + 1)) {
        infoNode->state = infoNode->state + 1;
        return true;
    }
    infoNode->state = BLE_GATT_CLIENT_INVALID;
    return false;
}

static SoftBusMessage *BleClientConnCreateLoopMsg(int32_t what, uint64_t arg1, uint64_t arg2, const char *data)
{
    SoftBusMessage *msg = NULL;
    msg = SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleClientConnCreateLoopMsg SoftBusCalloc failed");
        return NULL;
    }
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &g_bleClientAsyncHandler;
    msg->FreeMessage = FreeBleClientMessage;
    msg->obj = (void *)data;
    return msg;
}

static void ConnectedMsgHandler(int32_t clientId, int status)
{
    g_bleClientAsyncHandler.looper->RemoveMessageCustom(g_bleClientAsyncHandler.looper,
        &g_bleClientAsyncHandler, BleCilentRemoveMessageFunc, (void*)(uintptr_t)clientId);
    BleGattcInfo *infoNode = NULL;
    int32_t errCode = 0;
    if (SoftBusMutexLock(&g_gattcInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
    }
    infoNode = GetBleGattcInfoByClientIdInner(clientId);
    if (infoNode == NULL) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleGattcInfoByClientId not exist");
        return;
    }

    if ((status != SOFTBUS_GATT_SUCCESS) ||
        (UpdateBleGattcInfoStateInner(infoNode, BLE_GATT_CLIENT_STARTED) != true)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConnectedMsgHandler error");
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_GATTCLIENT_UPDATA_STATE_ERR);
        errCode = SOFTBUS_BLECONNECTION_CLIENT_UPDATA_STATE_ERR;
        goto EXIT;
    }
    if (SoftbusGattcSearchServices(clientId) != SOFTBUS_OK) {
        errCode = SOFTBUS_BLECONNECTION_CLIENT_SEARCH_SERVICES_ERR;
        goto EXIT;
    }
    if (BleClientPostMsgDelay(CLIENT_TIME_OUT, infoNode->clientId,
        SOFTBUS_BLECONNECTION_CLIENT_SERVICE_SEARCHED_TIMEOUT, CLIENT_SERVICE_SEARCHED_WAIT_TIME) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "post msg delay err");
        errCode = SOFTBUS_BLECONNECTION_CLIENT_CREATE_DELAY_MSG_ERR;
        goto EXIT;
    }
    if (UpdateBleGattcInfoStateInner(infoNode, BLE_GATT_CLIENT_SERVICE_SEARCHING) != true) {
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_GATTCLIENT_UPDATA_STATE_ERR);
        errCode = SOFTBUS_BLECONNECTION_CLIENT_UPDATA_STATE_ERR;
        goto EXIT;
    }
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    return;
EXIT:
    g_gattcInfoList->cnt--;
    ListDelete(&(infoNode->node));
    SoftBusFree(infoNode);
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    (void)SoftbusGattcUnRegister(clientId);
    BleHalConnInfo halConnInfo;
    halConnInfo.halConnId = clientId;
    halConnInfo.isServer = BLE_CLIENT_TYPE;
    (void)g_softBusBleConnCb->BleDisconnectCallback(halConnInfo, errCode);
}

static int32_t BleClientRegisterOnce(int32_t clientId, SoftBusBtUuid *serverUuid, SoftBusBtUuid *connUuid)
{
    if (serverUuid == NULL || connUuid == NULL || serverUuid->uuid == NULL || connUuid->uuid == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleClientRegisterOnce invalid param");
        return SOFTBUS_ERR;
    }
    if (SoftbusGattcGetService(clientId, serverUuid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusGattcGetService failed");
        return SOFTBUS_ERR;
    }
    if (SoftbusGattcRegisterNotification(clientId, serverUuid, connUuid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "bleGattcRegisterNotification connUuid error");
        return SOFTBUS_ERR;
    }

    if (BleClientPostMsgDelay(CLIENT_TIME_OUT, clientId, SOFTBUS_BLECONNECTION_CLIENT_NOTIFICATED_ONCE_TIMEOUT,
        CLIENT_NOTIFICATED_ONCE_WAIT_TIME) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "post msg delay err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void SearchedMsgHandler(int32_t clientId, int status)
{
    g_bleClientAsyncHandler.looper->RemoveMessageCustom(g_bleClientAsyncHandler.looper,
        &g_bleClientAsyncHandler, BleCilentRemoveMessageFunc, (void*)(uintptr_t)clientId);
    BleGattcInfo *infoNode = NULL;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "%d  %d", clientId, status);
    if (SoftBusMutexLock(&g_gattcInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
    }
    infoNode = GetBleGattcInfoByClientIdInner(clientId);
    if (infoNode == NULL) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleGattcInfoByClientId not exist");
        return;
    }
    if (infoNode->state != BLE_GATT_CLIENT_SERVICE_SEARCHING) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid process for client:%d", clientId);
        return;
    }
    if (UpdateBleGattcInfoStateInner(infoNode, BLE_GATT_CLIENT_SERVICE_SEARCHED) != true) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "UpdateBleGattcInfoStateInner failed");
        return;
    }
    SoftBusBtUuid serverUuid;
    SoftBusBtUuid connUuid;
    serverUuid.uuid = SOFTBUS_SERVICE_UUID;
    serverUuid.uuidLen = strlen(SOFTBUS_SERVICE_UUID);
    connUuid.uuid = SOFTBUS_CHARA_BLECONN_UUID;
    connUuid.uuidLen = strlen(SOFTBUS_SERVICE_UUID);
    if (status != SOFTBUS_GATT_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid status:%d", status);
        goto EXIT;
    }
    if (BleClientRegisterOnce(clientId, &serverUuid, &connUuid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleClientRegisterOnce failed");
        goto EXIT;
    }

    (void)UpdateBleGattcInfoStateInner(infoNode, BLE_GATT_CLIENT_NOTIFICATING_ONCE);
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    return;
EXIT:
    infoNode->state = BLE_GATT_CLIENT_STOPPING;
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    (void)SoftbusBleGattcDisconnect(clientId);
}

static int32_t NotificatedOnceHandler(BleGattcInfo *infoNode)
{
    SoftBusBtUuid serverUuid;
    SoftBusBtUuid netUuid;
    serverUuid.uuid = SOFTBUS_SERVICE_UUID;
    serverUuid.uuidLen = strlen(SOFTBUS_SERVICE_UUID);
    netUuid.uuid = SOFTBUS_CHARA_BLENET_UUID;
    netUuid.uuidLen = strlen(SOFTBUS_SERVICE_UUID);
    if (SoftbusGattcRegisterNotification(infoNode->clientId, &serverUuid, &netUuid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusGattcRegisterNotification failed");
        return SOFTBUS_ERR;
    }
    if (BleClientPostMsgDelay(CLIENT_TIME_OUT, infoNode->clientId,
        SOFTBUS_BLECONNECTION_CLIENT_NOTIFICATED_TWICE_TIMEOUT, CLIENT_NOTIFICATED_TWICE_WAIT_TIME) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "post msg delay err");
        return SOFTBUS_ERR;
    }
    if (UpdateBleGattcInfoStateInner(infoNode, BLE_GATT_CLIENT_NOTIFICATING_TWICE) != true) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "UpdateBleGattcInfoStateInner failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t NotificatedTwiceHandler(BleGattcInfo *infoNode)
{
    if (UpdateBleGattcInfoStateInner(infoNode, BLE_GATT_CLIENT_MTU_SETTING) != true) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "UpdateBleGattcInfoStateInner failed");
        return SOFTBUS_ERR;
    }
    if (SoftbusGattcConfigureMtuSize(infoNode->clientId, DEFAULT_MTU_SIZE) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (BleClientPostMsgDelay(CLIENT_TIME_OUT, infoNode->clientId,
        SOFTBUS_BLECONNECTION_CLIENT_MTU_SETTED_TIMEOUT, CLIENT_MTU_SETTED_WAIT_TIME) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "post msg delay err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}


static void NotificatedMsgHandler(int32_t clientId, int status)
{
    g_bleClientAsyncHandler.looper->RemoveMessageCustom(g_bleClientAsyncHandler.looper,
        &g_bleClientAsyncHandler, BleCilentRemoveMessageFunc, (void*)(uintptr_t)clientId);
    BleGattcInfo *infoNode = NULL;
    if (SoftBusMutexLock(&g_gattcInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
    }
    infoNode = GetBleGattcInfoByClientIdInner(clientId);
    if (infoNode == NULL) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleGattcInfoByClientId not exist");
        return;
    }

    if (infoNode->state != BLE_GATT_CLIENT_NOTIFICATING_ONCE &&
        infoNode->state != BLE_GATT_CLIENT_NOTIFICATING_TWICE) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid process for client:%d", clientId);
        return;
    }
    (void)UpdateBleGattcInfoStateInner(infoNode, infoNode->state + 1);
    if (status != SOFTBUS_GATT_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "NotificatedMsgHandler error");
        goto EXIT;
    }
    if ((infoNode->state == BLE_GATT_CLIENT_NOTIFICATED_ONCE) &&
        (NotificatedOnceHandler(infoNode) != SOFTBUS_OK)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "NotificatedOnceHandler error");
        goto EXIT;
    }
    if ((infoNode->state == BLE_GATT_CLIENT_NOTIFICATED_TWICE) &&
        (NotificatedTwiceHandler(infoNode) != SOFTBUS_OK)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "NotificatedTwiceHandler error");
        goto EXIT;
    }
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    return;
EXIT:
    infoNode->state = BLE_GATT_CLIENT_STOPPING;
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    (void)SoftbusBleGattcDisconnect(clientId);
}

static void DisconnectedMsgHandler(int32_t clientId, int status)
{
    g_bleClientAsyncHandler.looper->RemoveMessageCustom(g_bleClientAsyncHandler.looper,
        &g_bleClientAsyncHandler, BleCilentRemoveMessageFunc, (void*)(uintptr_t)clientId);
    BleGattcInfo *infoNode = NULL;
    if (SoftBusMutexLock(&g_gattcInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
    }
    infoNode = GetBleGattcInfoByClientIdInner(clientId);
    if (infoNode == NULL) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleGattcInfoByClientId not exist");
        return;
    }
    if ((status != SOFTBUS_GATT_SUCCESS) ||
        (UpdateBleGattcInfoStateInner(infoNode, BLE_GATT_CLIENT_STOPPING) != true)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Passavie disconnect!clientId=%d", clientId);
    }
    g_gattcInfoList->cnt--;
    ListDelete(&(infoNode->node));
    SoftBusFree(infoNode);
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    (void)SoftbusGattcUnRegister(clientId);
    BleHalConnInfo halConnInfo;
    halConnInfo.halConnId = clientId;
    halConnInfo.isServer = BLE_CLIENT_TYPE;
    (void)g_softBusBleConnCb->BleDisconnectCallback(halConnInfo, SOFTBUS_BLECONNECTION_CLIENT_RECV_DISCONNECT_MSG);
}

static void MtuSettedMsgHandler(int32_t clientId, int32_t mtuSize)
{
    g_bleClientAsyncHandler.looper->RemoveMessageCustom(g_bleClientAsyncHandler.looper,
        &g_bleClientAsyncHandler, BleCilentRemoveMessageFunc, (void*)(uintptr_t)clientId);
    BleGattcInfo *infoNode = NULL;
    char bleStrMac[BT_MAC_LEN];
    if (SoftBusMutexLock(&g_gattcInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
    }
    infoNode = GetBleGattcInfoByClientIdInner(clientId);
    if (infoNode == NULL) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleGattcInfoByClientId not exist");
        return;
    }
    if (UpdateBleGattcInfoStateInner(infoNode, BLE_GATT_CLIENT_MTU_SETTED) != true) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid process for client:%d", clientId);
        return;
    }
    (void)UpdateBleGattcInfoStateInner(infoNode, BLE_GATT_CLIENT_CONNECTED);
    if (ConvertBtMacToStr(bleStrMac, BT_MAC_LEN, infoNode->peerAddr.addr, BT_ADDR_LEN) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Convert ble addr failed");
        return;
    }
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    
    g_softBusBleConnCb->BleConnectCallback(clientId, bleStrMac, &(infoNode->peerAddr));
}

static void TimeOutMsgHandler(int32_t clientId, int32_t errCode)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ble connect timeout, errcode:%d", errCode);
    BleGattcInfo *infoNode = NULL;
    if (SoftBusMutexLock(&g_gattcInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
    }
    infoNode = GetBleGattcInfoByClientIdInner(clientId);
    if (infoNode == NULL) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleGattcInfoByClientId not exist");
        return;
    }

    g_gattcInfoList->cnt--;
    ListDelete(&(infoNode->node));
    SoftBusFree(infoNode);
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    (void)SoftbusGattcUnRegister(clientId);
    BleHalConnInfo halConnInfo;
    halConnInfo.halConnId = clientId;
    halConnInfo.isServer = BLE_CLIENT_TYPE;
    (void)g_softBusBleConnCb->BleDisconnectCallback(halConnInfo, errCode);
    SoftbusBleGattcDisconnect(clientId);
}

static void BleGattcMsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, " 11ble gattc conn loop process msg type %d", msg->what);
    switch (msg->what) {
        case CLIENT_CONNECTED:
            ConnectedMsgHandler((int32_t)msg->arg1, (int32_t)msg->arg2);
            break;
        case CLIENT_SERVICE_SEARCHED:
            SearchedMsgHandler((int32_t)msg->arg1, (int32_t)msg->arg2);
            break;
        case CLIENT_NOTIFICATED:
            NotificatedMsgHandler((int32_t)msg->arg1, (int32_t)msg->arg2);
            break;
        case CLIENT_DISCONNECTED:
            DisconnectedMsgHandler((int32_t)msg->arg1, (int32_t)msg->arg2);
            break;
        case CLIENT_MTU_SETTED:
            MtuSettedMsgHandler((int32_t)msg->arg1, (int32_t)msg->arg2);
            break;
        case CLIENT_TIME_OUT: {
            BleCilentErrCode *info = (BleCilentErrCode *)msg->obj;
            if (info == NULL) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "msg what is CLIENT_TIME_OUT and obj is NULL");
                return;
            }
            TimeOutMsgHandler((int32_t)msg->arg1, (int32_t)info->errCode);
            break;
        }
        default:
            break;
    }
}

static void BleGattcConnStateCallback(int32_t clientId, int32_t state, int32_t status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConnStateCallback ble gattc id=%d,state=%d,status=%d\n",
        clientId, state, status);
    if (state == SOFTBUS_BT_CONNECT) {
        SoftBusMessage *msg = BleClientConnCreateLoopMsg(CLIENT_CONNECTED, clientId, status, NULL);
        if (msg == NULL) {
            return;
        }
        g_bleClientAsyncHandler.looper->PostMessage(g_bleClientAsyncHandler.looper, msg);
    }
    if (state == SOFTBUS_BT_DISCONNECT) {
        SoftBusMessage *msg = BleClientConnCreateLoopMsg(CLIENT_DISCONNECTED, clientId, status, NULL);
        if (msg == NULL) {
            return;
        }
        g_bleClientAsyncHandler.looper->PostMessage(g_bleClientAsyncHandler.looper, msg);
    }
}

static void BleGattcSearchServiceCallback(int32_t clientId, int32_t status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleGattcSearchServiceCallback id=%d,status=%d\n",
        clientId, status);
    SoftBusMessage *msg = BleClientConnCreateLoopMsg(CLIENT_SERVICE_SEARCHED, clientId, status, NULL);
    if (msg == NULL) {
        return;
    }
    g_bleClientAsyncHandler.looper->PostMessage(g_bleClientAsyncHandler.looper, msg);
}

static void BleGattcRegisterNotificationCallback(int32_t clientId, int32_t status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleGattcRegisterNotificationCallback id=%d,status=%d\n",
        clientId, status);
    SoftBusMessage *msg = BleClientConnCreateLoopMsg(CLIENT_NOTIFICATED, clientId, status, NULL);
    if (msg == NULL) {
        return;
    }
    g_bleClientAsyncHandler.looper->PostMessage(g_bleClientAsyncHandler.looper, msg);
}

static void BleGattcConfigureMtuSizeCallback(int32_t clientId, int32_t mtuSize, int32_t status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleGattcConfigureMtuSizeCallback id=%d,status=%d\n",
        clientId, status);
    if (status != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleGattcConfigureMtuSizeCallback status error:%d", status);
        return;
    }
    SoftBusMessage *msg = BleClientConnCreateLoopMsg(CLIENT_MTU_SETTED, clientId, mtuSize, NULL);
    if (msg == NULL) {
        return;
    }
    g_bleClientAsyncHandler.looper->PostMessage(g_bleClientAsyncHandler.looper, msg);
}

static int32_t GetMouduleFlags(SoftBusBtUuid *charaUuid, bool *flag)
{
    if (memcmp(charaUuid->uuid, SOFTBUS_CHARA_BLECONN_UUID, charaUuid->uuidLen) == 0) {
        *flag = true;
        return SOFTBUS_OK;
    }
    if (memcmp(charaUuid->uuid, SOFTBUS_CHARA_BLENET_UUID, charaUuid->uuidLen) == 0) {
        *flag = false;
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

static void BleGattcNotificationReceiveCallback(int32_t clientId, SoftBusGattcNotify *param, int32_t status)
{
    BleGattcInfo *infoNode = NULL;
    if (SoftBusMutexLock(&g_gattcInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return;
    }
    infoNode = GetBleGattcInfoByClientIdInner(clientId);
    if (infoNode == NULL) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleGattcInfoByClientId not exist");
        return;
    }
    if ((status != SOFTBUS_GATT_SUCCESS) || infoNode->state != BLE_GATT_CLIENT_CONNECTED) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "111BleGattcNotificationReceiveCallback error");
        return;
    }
    bool isBleConn;
    if (GetMouduleFlags(&(param->charaUuid), &isBleConn) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGattcNotificationReceiveCallback uuid error");
        return;
    }
    uint32_t len;
    int32_t index = -1;
    BleHalConnInfo halConnInfo;
    halConnInfo.halConnId = clientId;
    halConnInfo.isServer = BLE_CLIENT_TYPE;
    char *value = BleTransRecv(halConnInfo, (char *)param->data,
        (uint32_t)param->dataLen, &len, &index);
    if (value == NULL) {
        (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "data not enough");
        return;
    }
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);

    (void)g_softBusBleConnCb->BleOnDataReceived(isBleConn, halConnInfo, (uint32_t)len, (char *)value);
    if (index != -1) {
        BleTransCacheFree(halConnInfo, index);
    }
}

static int BleConnClientLooperInit(void)
{
    g_bleClientAsyncHandler.looper = CreateNewLooper("ble_gattc_looper");
    if (g_bleClientAsyncHandler.looper == NULL) {
        return SOFTBUS_ERR;
    }
    g_bleClientAsyncHandler.HandleMessage = BleGattcMsgHandler;
    return SOFTBUS_OK;
}

static void RegistGattcCallback(SoftBusBleConnCalback *cb)
{
    g_softbusGattcCb.ConnectionStateCallback = BleGattcConnStateCallback;
    g_softbusGattcCb.ServiceCompleteCallback = BleGattcSearchServiceCallback;
    g_softbusGattcCb.RegistNotificationCallback = BleGattcRegisterNotificationCallback;
    g_softbusGattcCb.NotificationReceiveCallback = BleGattcNotificationReceiveCallback;
    g_softbusGattcCb.ConfigureMtuSizeCallback = BleGattcConfigureMtuSizeCallback;
    SoftbusGattcRegisterCallback(&g_softbusGattcCb);
    g_softBusBleConnCb = cb;
}

int32_t SoftBusGattClientInit(SoftBusBleConnCalback *cb)
{
    if (g_gattcIsInited == true) {
        return SOFTBUS_OK;
    }

    if (cb == NULL) {
        return SOFTBUS_ERR;
    }

    int ret = BleConnClientLooperInit();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    g_gattcInfoList = CreateSoftBusList();
    if (g_gattcInfoList == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "init ble gattc info list fail");
        return SOFTBUS_ERR;
    }
    RegistGattcCallback(cb);
    g_gattcIsInited = true;
    SoftBusRegConnVarDump(BLE_GATTC_INFO, &BleGattcDump);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "init gattc success!");
    return SOFTBUS_OK;
}

static int32_t BleGattcDump(int fd)
{
    char addr[UDID_BUF_LEN] = {0};
    if (SoftBusMutexLock(&g_gattcInfoList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return SOFTBUS_LOCK_ERR;
    }
    ListNode *item = NULL;
    SOFTBUS_DPRINTF(fd, "\n-----------------BLEGattc Info-------------------\n");
    SOFTBUS_DPRINTF(fd, "g_gattcIsInited               : %d\n", g_gattcIsInited);
    LIST_FOR_EACH(item, &(g_gattcInfoList->list)) {
        BleGattcInfo *itemNode = LIST_ENTRY(item, BleGattcInfo, node);
        SOFTBUS_DPRINTF(fd, "clientId                  : %d\n", itemNode->clientId);
        SOFTBUS_DPRINTF(fd, "state                     : %d\n", itemNode->state);
        DataMasking((char *)itemNode->peerAddr.addr, UDID_BUF_LEN, ID_DELIMITER, addr);
        SOFTBUS_DPRINTF(fd, "btMac                     : %s\n", addr);
    }
    (void)SoftBusMutexUnlock(&g_gattcInfoList->lock);
    return SOFTBUS_OK;
}

void SoftbusGattcHandShakeEvent(int32_t clientId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SoftbusGattcHandShakeEvent, cilentId:%d", clientId);
    if (BleClientPostMsgDelay(CLIENT_TIME_OUT, clientId, SOFTBUS_BLECONNECTION_CLIENT_HANDSHAKE_TIMEOUT,
        CLIENT_HANDSHAKE_WAIT_TIME) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "post msg delay err");
    }
}

void SoftbusGattcOnRecvHandShakeRespon(int32_t clientId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SoftbusGattcOnRecvHandShakeRespon, cilentId:%d", clientId);
    g_bleClientAsyncHandler.looper->RemoveMessageCustom(g_bleClientAsyncHandler.looper, &g_bleClientAsyncHandler,
        BleCilentRemoveMessageFunc, (void*)(uintptr_t)clientId);
}
