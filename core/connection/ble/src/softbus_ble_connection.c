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
#include "softbus_ble_connection.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>

#include "bus_center_manager.h"
#include "cJSON.h"
#include "common_list.h"
#include "message_handler.h"
#include "securec.h"
#include "softbus_adapter_ble_gatt_server.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_timer.h"
#include "softbus_ble_gatt_client.h"
#include "softbus_ble_gatt_server.h"
#include "softbus_ble_queue.h"
#include "softbus_ble_trans_manager.h"
#include "softbus_conn_manager.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_datahead_transform.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_queue.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"
#include "softbus_hidumper_conn.h"
#include "softbus_hisysevt_connreporter.h"

#define SEND_QUEUE_UNIT_NUM 128
#define CONNECT_REF_INCRESE 1
#define CONNECT_REF_DECRESE (-1)
#define METHOD_NOTIFY_REQUEST 1
#define METHOD_NOTIFY_RESPONSE 2
#define METHOD_SHUT_DOWN 3
#define CONN_MAGIC_NUMBER  0xBABEFACE
#define KEY_METHOD "KEY_METHOD"
#define KEY_DELTA "KEY_DELTA"
#define KEY_REF_NUM "KEY_REF_NUM"
#define TYPE_HEADER_SIZE 4
#define INVALID_CLIENID (-1)
#define BLE_CONNECTION_INFO "BleConnectionInfo"
#define CONNECTED_WAIT_TIME (2 * 1000)

typedef enum {
    BLE_CONNECTION_STATE_CONNECTING = 0,
    BLE_CONNECTION_STATE_CONNECTED,
    BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED,
    BLE_CONNECTION_STATE_CLOSING,
    BLE_CONNECTION_STATE_CLOSED
} BleConnectionState;

typedef enum {
    TYPE_UNKNOW = -1,
    TYPE_AUTH = 0,
    TYPE_BASIC_INFO = 1,
    TYPE_DEV_INFO = 2,
} BleNetMsgType;

typedef enum {
    BLE_CONNECTION_DISCONNECT_OUT,
} BleConnectionLoopMsg;

static SoftBusHandler g_bleConnectAsyncHandler = {
    .name = (char *)"g_bleConnectAsyncHandler"
};

static const int BLE_GATT_ATT_MTU_DEFAULT_PAYLOAD = 21;
static const int BLE_GATT_ATT_MTU_MAX = 512;
static const int BLE_ROLE_CLIENT = 1;
static const int BLE_ROLE_SERVER = 2;

static LIST_HEAD(g_connection_list);
static ConnectCallback *g_connectCallback = NULL;
static ConnectFuncInterface g_bleInterface = {0};
static SoftBusMutex g_connectionLock;

static void PackRequest(int32_t delta, uint32_t connectionId);
static int32_t SendSelfBasicInfo(uint32_t connId, int32_t roleType);
static int32_t BleConnectionDump(int fd);
static int32_t BleConnectionRemoveMessageFunc(const SoftBusMessage *msg, void *args);

static uint32_t AllocBleConnectionIdLocked()
{
    static uint16_t nextConnectionId = 0;
    uint32_t tempId;
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return 0;
    }
    nextConnectionId++;
    while (1) {
        tempId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + nextConnectionId;
        ListNode *item = NULL;
        LIST_FOR_EACH(item, &g_connection_list) {
            BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
            if (itemNode->connId == tempId) {
                nextConnectionId++;
                continue;
            }
        }
        break;
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    return tempId;
}

static BleConnectionInfo* CreateBleConnectionNode(void)
{
    BleConnectionInfo *newConnectionInfo = (BleConnectionInfo *)SoftBusCalloc(sizeof(BleConnectionInfo));
    if (newConnectionInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[CreateBleConnectionNode malloc fail.]");
        return NULL;
    }
    ListInit(&newConnectionInfo->node);
    ListInit(&newConnectionInfo->requestList);
    newConnectionInfo->connId = AllocBleConnectionIdLocked();
    newConnectionInfo->mtu = BLE_GATT_ATT_MTU_DEFAULT_PAYLOAD;
    newConnectionInfo->refCount = 0;
    newConnectionInfo->info.isAvailable = 1;
    newConnectionInfo->info.type = CONNECT_BLE;
    return newConnectionInfo;
}

static void ReleaseBleconnectionNode(BleConnectionInfo *newConnectionInfo)
{
    if (newConnectionInfo == NULL) {
        return;
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ReleaseBleconnectionNode");
    BleRequestInfo *requestInfo = NULL;
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    if (IsListEmpty(&newConnectionInfo->requestList) != true) {
        LIST_FOR_EACH_SAFE(item, itemNext, &newConnectionInfo->requestList) {
            requestInfo = LIST_ENTRY(item, BleRequestInfo, node);
            ListDelete(&requestInfo->node);
            SoftBusFree(requestInfo);
        }
    }
    SoftBusFree(newConnectionInfo);
    return;
}

void DeleteBleConnectionNode(BleConnectionInfo* node)
{
    if (node == NULL) {
        return;
    }
    node->state = BLE_CONNECTION_STATE_CLOSED;
    for (int i = 0; i < MAX_CACHE_NUM_PER_CONN; i++) {
        if (node->recvCache[i].cache != NULL) {
            SoftBusFree(node->recvCache[i].cache);
        }
    }
    SoftBusFree(node);
}

static BleConnectionInfo* GetBleConnInfoByConnId(uint32_t connectionId)
{
    ListNode *item = NULL;
    BleConnectionInfo *itemNode = NULL;
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    LIST_FOR_EACH(item, &g_connection_list) {
        itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->connId == connectionId) {
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    return itemNode;
}

BleConnectionInfo* GetBleConnInfoByHalConnId(BleHalConnInfo halConnInfo)
{
    ListNode *item = NULL;
    BleConnectionInfo *itemNode = NULL;
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    LIST_FOR_EACH(item, &g_connection_list) {
        itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->halConnId == halConnInfo.halConnId && itemNode->info.isServer == halConnInfo.isServer) {
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    return itemNode;
}

static int32_t GetBleConnInfoByAddr(const char *strAddr, BleConnectionInfo **server, BleConnectionInfo **client)
{
    ListNode *item = NULL;
    BleConnectionInfo *itemNode = NULL;
    bool findServer = false;
    bool findClient = false;
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_BLECONNECTION_MUTEX_LOCK_ERROR;
    }
    LIST_FOR_EACH(item, &g_connection_list) {
        itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (memcmp(itemNode->info.bleInfo.bleMac, strAddr, BT_MAC_LEN) == 0) {
            if (itemNode->info.isServer) {
                *server = itemNode;
                findServer = true;
            } else {
                *client = itemNode;
                findClient = true;
            }
            if (findServer && findClient) {
                break;
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    return SOFTBUS_OK;
}

static int32_t GetBleConnInfoByDeviceIdHash(const char *deviceIdHash,
    BleConnectionInfo **server, BleConnectionInfo **client)
{
    ListNode *item = NULL;
    BleConnectionInfo *itemNode = NULL;
    bool findServer = false;
    bool findClient = false;
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_BLECONNECTION_MUTEX_LOCK_ERROR;
    }
    LIST_FOR_EACH(item, &g_connection_list) {
        itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (memcmp(itemNode->info.bleInfo.deviceIdHash, deviceIdHash, UDID_HASH_LEN) == 0) {
            if (itemNode->info.isServer) {
                *server = itemNode;
                findServer = true;
            } else {
                *client = itemNode;
                findClient = true;
            }
            if (findServer && findClient) {
                break;
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    return SOFTBUS_OK;
}


static void BleDeviceConnected(const BleConnectionInfo *itemNode, uint32_t requestId, const ConnectResult *result)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ble mac has connected");
    ConnectionInfo connectionInfo;
    connectionInfo.isAvailable = 1;
    connectionInfo.isServer = itemNode->info.isServer;
    connectionInfo.type = CONNECT_BLE;
    if (strcpy_s(connectionInfo.bleInfo.bleMac, BT_MAC_LEN, itemNode->info.bleInfo.bleMac) != EOK) {
        return;
    }
    int connectionId = itemNode->connId;

    if (result->OnConnectSuccessed != NULL) {
        result->OnConnectSuccessed(
            requestId, connectionId, &connectionInfo);
    }

    (void)PackRequest(CONNECT_REF_INCRESE, connectionId);
}

static BleRequestInfo *CreateBleRequestInfo(uint32_t requestId, const ConnectResult *result)
{
    BleRequestInfo *request = (BleRequestInfo *)SoftBusCalloc(sizeof(BleRequestInfo));
    if (request == NULL) {
        return NULL;
    }
    ListInit(&request->node);
    request->requestId = requestId;
    request->callback = *result;
    return request;
}

static BleConnectionInfo* NewBleConnection(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    BleConnectionInfo *newConnectionInfo = CreateBleConnectionNode();
    if (newConnectionInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create ble connection node failed, requestId: %d", requestId);
        return NULL;
    }
    newConnectionInfo->mtu = BLE_GATT_ATT_MTU_MAX;
    newConnectionInfo->state = BLE_CONNECTION_STATE_CONNECTING;
    newConnectionInfo->info.isServer = BLE_CLIENT_TYPE;
    if (strcpy_s(newConnectionInfo->info.bleInfo.bleMac, BT_MAC_LEN,
        option->bleOption.bleMac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed, requestId: %d", requestId);
        ReleaseBleconnectionNode(newConnectionInfo);
        return NULL;
    }
    if (ConvertBtMacToBinary(option->bleOption.bleMac, BT_MAC_LEN,
        newConnectionInfo->btBinaryAddr.addr, BT_ADDR_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "convert bt mac to binary failed, requestId: %d", requestId);
        ReleaseBleconnectionNode(newConnectionInfo);
        return NULL;
    }
    BleRequestInfo *requestInfo = CreateBleRequestInfo(requestId, result);
    if (requestInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "CreateBleRequestInfo failed, requestId: %d", requestId);
        ReleaseBleconnectionNode(newConnectionInfo);
        return NULL;
    }
    ListAdd(&newConnectionInfo->requestList, &requestInfo->node);
    return newConnectionInfo;
}

static int32_t UpdataBleConnectionUnsafe(const ConnectOption *option, int32_t halId, uint32_t requestId)
{
    BleConnectionInfo *server = NULL;
    BleConnectionInfo *client = NULL;
    if (GetBleConnInfoByAddr(option->bleOption.bleMac, &server, &client) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleConnInfoByAddr failed, requestId: %d", requestId);
        return SOFTBUS_ERR;
    }
    (void)server;
    if (client == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unexperted failure! there is no ble connection info, "
            "requestId: %d", requestId);
        return SOFTBUS_ERR;
    }
    if (halId < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "gatt client connect failed, ret: %d, requestId: %d",
            halId, requestId);
        ListDelete(&client->node);
        ReleaseBleconnectionNode(client);
        return SOFTBUS_ERR;
    }
    client->halConnId = halId;
    return SOFTBUS_OK;
}

static int32_t TryReuseConnectionOrWaitUnsafe(BleConnectionInfo *exist, uint32_t requestId,
    const ConnectResult *result)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "there is a ble connection processing, state: %d, requestId: %d",
        exist->state, requestId);

    if (exist->state == BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED) {
        BleDeviceConnected(exist, requestId, result);
        return SOFTBUS_OK;
    }
    if (exist->state == BLE_CONNECTION_STATE_CONNECTING || exist->state == BLE_CONNECTION_STATE_CONNECTED) {
        BleRequestInfo *requestInfo = CreateBleRequestInfo(requestId, result);
        if (requestInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "CreateBleRequestInfo failed, requestId: %d", requestId);
            return SOFTBUS_ERR;
        }
        ListAdd(&exist->requestList, &requestInfo->node);
        return SOFTBUS_OK;
    }
    if (exist->state == BLE_CONNECTION_STATE_CLOSING) {
        result->OnConnectFailed(requestId, 0);
        return SOFTBUS_OK;
    }

    return SOFTBUS_ERR;
}

static int32_t BleConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleConnectDevice, requestId=%d", requestId);
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: lock mutex failed, requestId: %d", __func__, requestId);
        return SOFTBUS_ERR;
    }
    BleConnectionInfo *server = NULL;
    BleConnectionInfo *client = NULL;
    if (GetBleConnInfoByAddr(option->bleOption.bleMac, &server, &client) != SOFTBUS_OK) {
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_CONNECT_FAIL);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetBleConnInfoByAddr failed, requestId: %d", requestId);
        SoftbusRecordConnInfo(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_EVT_CONN_FAIL, 0);
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return SOFTBUS_ERR;
    }
    (void)server;
    if (client != NULL) {
        int ret = TryReuseConnectionOrWaitUnsafe(client, requestId, result);
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return ret;
    }
    BleConnectionInfo *newConnectionInfo = NewBleConnection(option, requestId, result);
    if (newConnectionInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ble client node create fail, requestId: %d", requestId);
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_CONNECT_FAIL);
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return SOFTBUS_ERR;
    }
    uint32_t connId = newConnectionInfo->connId;
    ListAdd(&g_connection_list, &newConnectionInfo->node);
    (void)SoftBusMutexUnlock(&g_connectionLock);

    int32_t clientId = INVALID_CLIENID;
    clientId = SoftBusGattClientConnect(&(newConnectionInfo->btBinaryAddr), option->bleOption.fastestConnectEnable);

    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: lock mutex failed, requestId: %d", __func__, requestId);
        return SOFTBUS_ERR;
    }
    if (UpdataBleConnectionUnsafe(option, clientId, requestId) != SOFTBUS_OK) {
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_CONNECT_FAIL);
        SoftbusRecordConnInfo(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_EVT_CONN_FAIL, 0);
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return SOFTBUS_ERR;
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "new connection %d, clientId: %d, requesId: %d",
        connId, clientId, requestId);
    return SOFTBUS_OK;
}

static int32_t BlePostBytes(uint32_t connectionId, const char *data, int32_t len, int32_t pid, int32_t flag)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "BlePostBytes connectionId=%u,pid=%d,len=%d flag=%d", connectionId, pid, len, flag);
    if (data == NULL) {
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        SoftBusFree((void *)data);
        return SOFTBUS_ERR;
    }
    BleConnectionInfo *connInfo = GetBleConnInfoByConnId(connectionId);
    if (connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BlePostBytes GetBleConnInfo failed");
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_SEND_FAIL);
        SoftBusFree((void *)data);
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return SOFTBUS_BLECONNECTION_GETCONNINFO_ERROR;
    }
    SendQueueNode *node = (SendQueueNode *)SoftBusCalloc(sizeof(SendQueueNode));
    if (node == NULL) {
        SoftBusFree((void *)data);
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return SOFTBUS_MALLOC_ERR;
    }
    node->halConnId = connInfo->halConnId;
    node->connectionId = connectionId;
    node->isServer = connInfo->info.isServer;
    node->pid = pid;
    node->flag = flag;
    node->len = (uint32_t)len;
    node->data = data;
    node->isInner = 0;
    int ret = BleEnqueueNonBlock((const void *)node);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BlePostBytes enqueue failed");
        SoftBusFree((void *)data);
        SoftBusFree(node);
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return ret;
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    return SOFTBUS_OK;
}

static int32_t BlePostBytesInner(uint32_t connectionId, ConnPostData *data)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BlePostBytesInner connectionId=%u", connectionId);
    if (data == NULL) {
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    BleConnectionInfo *connInfo = GetBleConnInfoByConnId(connectionId);
    if (connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BlePostBytes GetBleConnInfo failed");
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return SOFTBUS_BLECONNECTION_GETCONNINFO_ERROR;
    }
    SendQueueNode *node = (SendQueueNode *)SoftBusCalloc(sizeof(SendQueueNode));
    if (node == NULL) {
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return SOFTBUS_MALLOC_ERR;
    }
    node->halConnId = connInfo->halConnId;
    node->connectionId = connectionId;
    node->isServer = connInfo->info.isServer;
    node->len = data->len;
    node->data = data->buf;
    node->isInner = 1;
    node->module = data->module;
    node->seq = data->seq;
    int ret = BleEnqueueNonBlock((const void *)node);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BlePostBytes enqueue failed");
        SoftBusFree(node);
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return ret;
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    return SOFTBUS_OK;
}

static int AddNumToJson(cJSON *json, int32_t requestOrResponse, int32_t delta, int32_t count)
{
    if (requestOrResponse == METHOD_NOTIFY_REQUEST) {
        if (!AddNumberToJsonObject(json, KEY_METHOD, METHOD_NOTIFY_REQUEST) ||
            !AddNumberToJsonObject(json, KEY_DELTA, delta) ||
            !AddNumberToJsonObject(json, KEY_REF_NUM, count)) {
            return SOFTBUS_BRCONNECTION_PACKJSON_ERROR;
        }
    } else {
        if (!AddNumberToJsonObject(json, KEY_METHOD, METHOD_NOTIFY_RESPONSE) ||
            !AddNumberToJsonObject(json, KEY_REF_NUM, count)) {
            return SOFTBUS_BRCONNECTION_PACKJSON_ERROR;
        }
    }
    return SOFTBUS_OK;
}

static void SendRefMessage(int32_t delta, int32_t connectionId, int32_t count, int32_t requestOrResponse)
{
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot create cJSON object");
        return;
    }
    if (AddNumToJson(json, requestOrResponse, delta, count) != SOFTBUS_OK) {
        cJSON_Delete(json);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot AddNumToJson");
        return;
    }
    char *data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "cJSON_PrintUnformatted failed");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendRefMessage:%s", data);
    uint32_t headSize = sizeof(ConnPktHead);
    uint32_t dataLen = strlen(data) + 1 + headSize;
    char *buf = (char *)SoftBusCalloc(dataLen);
    if (buf == NULL) {
        cJSON_free(data);
        return;
    }
    ConnPktHead head;
    head.magic = CONN_MAGIC_NUMBER;
    head.module = MODULE_CONNECTION;
    head.seq = 1;
    head.flag = 0;
    head.len = strlen(data) + 1;
    PackConnPktHead(&head);
    if (memcpy_s(buf, dataLen, (void *)&head, headSize) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s head error");
        cJSON_free(data);
        SoftBusFree(buf);
        return;
    }
    if (memcpy_s(buf + headSize, dataLen - headSize, data, strlen(data) + 1) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s data error");
        cJSON_free(data);
        SoftBusFree(buf);
        return;
    }
    cJSON_free(data);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendRefMessage BlePostBytes");
    if (BlePostBytes(connectionId, buf, dataLen, 0, 0) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendRefMessage BlePostBytes failed");
    }
    return;
}

static void PackRequest(int32_t delta, uint32_t connectionId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "[onNotifyRequest: delta=%d, connectionIds=%u", delta, connectionId);
    ListNode *item = NULL;
    BleConnectionInfo *targetNode = NULL;
    int refCount;
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    LIST_FOR_EACH(item, &g_connection_list) {
        BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->connId == connectionId) {
            itemNode->refCount += delta;
            refCount = itemNode->refCount;
            targetNode = itemNode;
            break;
        }
    }
    if (targetNode != NULL && refCount <= 0) {
        SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
        if (msg == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "bleConnectionCreateLoopMsg SoftBusCalloc failed");
            (void)SoftBusMutexUnlock(&g_connectionLock);
            return;
        }
        msg->what = BLE_CONNECTION_DISCONNECT_OUT;
        msg->arg1 = connectionId;
        msg->handler = &g_bleConnectAsyncHandler;
        g_bleConnectAsyncHandler.looper->PostMessageDelay(g_bleConnectAsyncHandler.looper, msg, CONNECTED_WAIT_TIME);

        targetNode->state = BLE_CONNECTION_STATE_CLOSING;
    }

    (void)SoftBusMutexUnlock(&g_connectionLock);
    if (targetNode == NULL) {
        return;
    }

    SendRefMessage(delta, connectionId, refCount, METHOD_NOTIFY_REQUEST);
}

static void AbortConnection(SoftBusBtAddr btAddr, int32_t halConnId, int32_t isServer)
{
    if (isServer == BLE_CLIENT_TYPE) {
        SoftBusGattClientDisconnect(halConnId);
    }
    SoftBusGattsDisconnect(btAddr, halConnId);
}

static void OnPackResponse(int32_t delta, int32_t peerRef, uint32_t connectionId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "[onNotifyRequest: delta=%d, RemoteRef=%d, connectionIds=%u", delta, peerRef, connectionId);
    ListNode *item = NULL;
    BleConnectionInfo *targetNode = NULL;
    int myRefCount;
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    LIST_FOR_EACH(item, &g_connection_list) {
        BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->connId == connectionId) {
            targetNode = itemNode;
            targetNode->refCount += delta;
            myRefCount = targetNode->refCount;
            break;
        }
    }
    if (targetNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Not find OnPackResponse device");
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return;
    }
    if (peerRef > 0 && targetNode->state == BLE_CONNECTION_STATE_CLOSING) {
        g_bleConnectAsyncHandler.looper->RemoveMessageCustom(g_bleConnectAsyncHandler.looper,
            &g_bleConnectAsyncHandler, BleConnectionRemoveMessageFunc, (void*)(uintptr_t)connectionId);

        targetNode->state = BLE_CONNECTION_STATE_CONNECTED;
    }

    (void)SoftBusMutexUnlock(&g_connectionLock);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[onPackRequest: myRefCount=%d]", myRefCount);
    if (peerRef > 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[remote device Ref is > 0, do not reply]");
        return;
    }
    if (myRefCount <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[local device Ref <= 0, close connection now]");
        targetNode->state = BLE_CONNECTION_STATE_CLOSING;
        AbortConnection(targetNode->btBinaryAddr, targetNode->halConnId, targetNode->info.isServer);
        return;
    }
    SendRefMessage(delta, connectionId, myRefCount, METHOD_NOTIFY_RESPONSE);
}

static void RecvConnectedComd(uint32_t connectionId, const cJSON *data)
{
    int32_t keyMethod = 0;
    int32_t keyDelta = 0;
    int32_t keyReferenceNum = 0;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RecvConnectedComd ID=%u", connectionId);

    if (!GetJsonObjectNumberItem(data, KEY_METHOD, &keyMethod)) {
        return;
    }
    if (keyMethod == METHOD_NOTIFY_REQUEST) {
        if (!GetJsonObjectNumberItem(data, KEY_METHOD, &keyMethod) ||
            !GetJsonObjectSignedNumberItem(data, KEY_DELTA, &keyDelta) ||
            !GetJsonObjectNumberItem(data, KEY_REF_NUM, &keyReferenceNum)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "REQUEST fail");
            return;
        }
        OnPackResponse(keyDelta, keyReferenceNum, connectionId);
    }
    if (keyMethod == METHOD_NOTIFY_RESPONSE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "NOTIFY_RESPONSE");
        if (!GetJsonObjectNumberItem(data, KEY_METHOD, &keyMethod) ||
            !GetJsonObjectNumberItem(data, KEY_REF_NUM, &keyReferenceNum)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RESPONSE fail");
            return;
        }
        (void)SoftBusMutexLock(&g_connectionLock);
        ListNode *item = NULL;
        LIST_FOR_EACH(item, &g_connection_list) {
            BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
            if (itemNode->connId == connectionId) {
                if (itemNode->state == BLE_CONNECTION_STATE_CLOSING) {
                    g_bleConnectAsyncHandler.looper->RemoveMessageCustom(g_bleConnectAsyncHandler.looper,
                        &g_bleConnectAsyncHandler, BleConnectionRemoveMessageFunc, (void*)(uintptr_t)connectionId);
                    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "NOTIFY_CHANGE");
                    itemNode->state = BLE_CONNECTION_STATE_CONNECTED;
                }
                break;
            }
        }
        (void)SoftBusMutexUnlock(&g_connectionLock);
    }
}

static int32_t BleDisconnectDevice(uint32_t connectionId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[DisconnectDevice]");
    BleConnectionInfo *connInfo = GetBleConnInfoByConnId(connectionId);
    if (connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleDisconnectDevice GetBleConnInfo failed");
        return SOFTBUS_BLECONNECTION_GETCONNINFO_ERROR;
    }
    (void)PackRequest(CONNECT_REF_DECRESE, connectionId);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[DisconnectDevice over]");
    return SOFTBUS_OK;
}

static int32_t BleDisconnectDeviceNow(const ConnectOption *option)
{
    int32_t ret;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[DisconnectDeviceByOption]");
    BleConnectionInfo *server = NULL;
    BleConnectionInfo *client = NULL;
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    ret = GetBleConnInfoByAddr(option->bleOption.bleMac, &server, &client);
    if ((ret != SOFTBUS_OK) || ((server == NULL) && (client == NULL))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleDisconnectDevice GetBleConnInfo failed");
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_DISCONNECT_FAIL);
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return SOFTBUS_BLECONNECTION_GETCONNINFO_ERROR;
    }
    if (server != NULL) {
        server->state = BLE_CONNECTION_STATE_CLOSING;
        SoftBusBtAddr binAddr = server->btBinaryAddr;
        int32_t halId = server->halConnId;
        (void)SoftBusMutexUnlock(&g_connectionLock);
        SoftBusGattsDisconnect(binAddr, halId);
    } else {
        client->state = BLE_CONNECTION_STATE_CLOSING;
        int32_t halId = client->halConnId;
        (void)SoftBusMutexUnlock(&g_connectionLock);
        SoftBusGattClientDisconnect(halId);
    }
    return ret;
}

static int32_t BleGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    int32_t result = SOFTBUS_ERR;
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->connId == connectionId) {
            if (memcpy_s(info, sizeof(ConnectionInfo), &(itemNode->info), sizeof(ConnectionInfo)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGetConnInfo scpy error");
                (void)SoftBusMutexUnlock(&g_connectionLock);
                return SOFTBUS_BLECONNECTION_GETCONNINFO_ERROR;
            }
            result = SOFTBUS_OK;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    return result;
}

static int32_t BleStartLocalListening(const LocalListenerInfo *info)
{
    return SoftBusGattServerStartService();
}

static int32_t BleStopLocalListening(const LocalListenerInfo *info)
{
    return SoftBusGattServerStopService();
}

static bool BleCheckActiveConnection(const ConnectOption *option)
{
    if (option == NULL || option->type != CONNECT_BLE) {
        return false;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleCheckActiveConnection");
    int32_t ret;
    BleConnectionInfo *server = NULL;
    BleConnectionInfo *client = NULL;

    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        return false;
    }
    ret = GetBleConnInfoByDeviceIdHash(option->bleOption.deviceIdHash, &server, &client);
    if ((ret != SOFTBUS_OK) || (server == NULL && client == NULL)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleCheckActiveConnection no active conn");
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return false;
    }
    if ((server != NULL && server->state == BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED) ||
        (client != NULL && client->state == BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED)) {
        (void)SoftBusMutexUnlock(&g_connectionLock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleCheckActiveConnection had active conn");
        return true;
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleCheckActiveConnection no active conn");
    return false;
}

static int32_t BleUpdateConnection(uint32_t connectionId, UpdateOption *option)
{
    BleConnectionInfo *connInfo = GetBleConnInfoByConnId(connectionId);
    if (connInfo == NULL) {
        CLOGE("update ble connection failed, %u not exist", connectionId);
        return SOFTBUS_ERR;
    }
    if (connInfo->state != BLE_CONNECTION_STATE_CONNECTED &&
        connInfo->state != BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED) {
        CLOGE("update ble connection failed, %u current state is %d, only %d or %d support", connectionId,
            connInfo->state, BLE_CONNECTION_STATE_CONNECTED, BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED);
        return SOFTBUS_ERR;
    }
    if (connInfo->info.isServer) {
        CLOGE("update ble connection failed, %u is server side, only client side support", connectionId);
        return SOFTBUS_ERR;
    }

    SoftbusGattPriority priority;
    switch (option->bleOption.priority) {
        case CONN_BLE_PRIORITY_BALANCED:
            priority = SOFTBUS_GATT_PRIORITY_BALANCED;
            break;
        case CONN_BLE_PRIORITY_HIGH:
            priority = SOFTBUS_GATT_PRIORITY_HIGH;
            break;
        case CONN_BLE_PRIORITY_LOW_POWER:
            priority = SOFTBUS_GATT_PRIORITY_LOW_POWER;
            break;
        default:
            CLOGE("update ble connection failed, %u, unknown priority: %d", connectionId, option->bleOption.priority);
            return SOFTBUS_ERR;
    }
    int32_t ret = SoftbusGattcSetPriority(connInfo->halConnId, &connInfo->btBinaryAddr, priority);
    CLOGI("set ble connection priority to %d, ret=%d", priority, ret);
    return ret;
}

static void BleDeviceConnectPackRequest(int32_t value, int32_t connId)
{
    int32_t data = value;
    while (data-- > 0) {
        (void)PackRequest(CONNECT_REF_INCRESE, connId);
    }
}

static void BleClientConnectCallback(int32_t halConnId, const char *bleStrMac, const SoftBusBtAddr *btAddr)
{
    ListNode *bleItem = NULL;
    (void)SoftBusMutexLock(&g_connectionLock);
    uint32_t connId = 0;
    LIST_FOR_EACH(bleItem, &g_connection_list) {
        BleConnectionInfo *itemNode = LIST_ENTRY(bleItem, BleConnectionInfo, node);
        if (itemNode->halConnId != halConnId || itemNode->info.isServer != BLE_CLIENT_TYPE) {
            continue;
        }
        connId = itemNode->connId;
        itemNode->state = BLE_CONNECTION_STATE_CONNECTED;
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    SoftbusGattcHandShakeEvent(halConnId);
    if (SendSelfBasicInfo(connId, BLE_ROLE_CLIENT) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendSelfBasicInfo error");
    }
}

static void BleClientDoneConnect(BleConnectionInfo *targetNode)
{
    ListNode notifyList;
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    BleRequestInfo *requestInfo = NULL;
    int32_t packRequestFlag = 0;
    ListInit(&notifyList);
    LIST_FOR_EACH_SAFE(item, itemNext, &targetNode->requestList) {
        requestInfo = LIST_ENTRY(item, BleRequestInfo, node);
        ListDelete(&requestInfo->node);
        ListAdd(&notifyList, &requestInfo->node);
        packRequestFlag++;
    }
    if (packRequestFlag == 0) {
        return;
    }
    BleDeviceConnectPackRequest(packRequestFlag, targetNode->connId);
    LIST_FOR_EACH_SAFE(item, itemNext, &notifyList) {
        requestInfo = LIST_ENTRY(item, BleRequestInfo, node);
        if (requestInfo->callback.OnConnectSuccessed != NULL) {
            requestInfo->callback.OnConnectSuccessed(
                requestInfo->requestId, targetNode->connId, &targetNode->info);
        }
        ListDelete(&requestInfo->node);
        SoftBusFree(requestInfo);
    }
}

static void BleServerConnectCallback(int32_t halConnId, const char *bleStrMac, const SoftBusBtAddr *btAddr)
{
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->halConnId == halConnId && itemNode->info.isServer == BLE_SERVER_TYPE) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleConnectCallback exist same connId, exit");
            (void)SoftBusMutexUnlock(&g_connectionLock);
            return;
        }
    }
    BleConnectionInfo *newNode = CreateBleConnectionNode();
    if (newNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ble client node create fail");
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return;
    }
    newNode->halConnId = halConnId;
    if (memcpy_s(newNode->btBinaryAddr.addr, BT_ADDR_LEN, btAddr->addr, BT_ADDR_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleConnectCallback memcpy_s error");
        SoftBusFree(newNode);
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return;
    }
    if (memcpy_s(newNode->info.bleInfo.bleMac, BT_MAC_LEN, bleStrMac, BT_MAC_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleConnectCallback memcpy_s error");
        SoftBusFree(newNode);
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return;
    }
    newNode->info.isServer = BLE_SERVER_TYPE;
    newNode->state = BLE_CONNECTION_STATE_CONNECTED;
    ListTailInsert(&g_connection_list, &(newNode->node));
    (void)SoftBusMutexUnlock(&g_connectionLock);
}

static void ReleaseBleConnectionInfo(BleConnectionInfo *info)
{
    if (info == NULL) {
        return;
    }
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    ListDelete(&info->node);
    LIST_FOR_EACH_SAFE(item, nextItem, &info->requestList) {
        BleRequestInfo *requestInfo = LIST_ENTRY(item, BleRequestInfo, node);
        ListDelete(&(requestInfo->node));
        SoftBusFree(requestInfo);
    }
    SoftBusFree(info);
}

static void BleNotifyDisconnect(const ListNode *notifyList, int32_t connectionId,
    ConnectionInfo connectionInfo, int32_t errCode)
{
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    if (IsListEmpty(notifyList) != true) {
        LIST_FOR_EACH_SAFE(item, itemNext, notifyList) {
            BleRequestInfo *requestInfo = LIST_ENTRY(item, BleRequestInfo, node);
            if (requestInfo->callback.OnConnectFailed != NULL) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[BleNotifyDisconnect]connectionId=%d", connectionId);
                requestInfo->callback.OnConnectFailed(requestInfo->requestId, errCode);
            }
            ListDelete(&requestInfo->node);
            SoftBusFree(requestInfo);
        }
    }

    if (g_connectCallback != NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[BleNotifyDisconnect] disconn connectionId=%d", connectionId);
        g_connectCallback->OnDisconnected(connectionId, &connectionInfo);
    }
}

static void BleDisconnectCallback(BleHalConnInfo halConnInfo, int32_t errCode)
{
    ListNode *bleItem = NULL;
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    uint32_t connectionId = 0;
    ListNode notifyList;
    ListInit(&notifyList);
    ConnectionInfo connectionInfo;
    BleConnectionInfo *bleNode = NULL;
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleDisconnectCallback mutex failed");
        return;
    }
    LIST_FOR_EACH(bleItem, &g_connection_list) {
        BleConnectionInfo *itemNode = LIST_ENTRY(bleItem, BleConnectionInfo, node);
        if (itemNode->halConnId == halConnInfo.halConnId && itemNode->info.isServer == halConnInfo.isServer) {
            bleNode = itemNode;
            itemNode->state = BLE_CONNECTION_STATE_CLOSED;
            if (memcpy_s(&connectionInfo, sizeof(ConnectionInfo), &(itemNode->info), sizeof(ConnectionInfo)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleDisconnectCallback memcpy_s fail");
                return;
            }
            connectionId = itemNode->connId;
            connectionInfo.isAvailable = 0;
            LIST_FOR_EACH_SAFE(item, itemNext, &itemNode->requestList) {
                BleRequestInfo *requestInfo = LIST_ENTRY(item, BleRequestInfo, node);
                ListDelete(&requestInfo->node);
                ListAdd(&notifyList, &requestInfo->node);
            }
            break;
        }
    }
    ReleaseBleConnectionInfo(bleNode);
    if (connectionId != 0) {
        BleNotifyDisconnect(&notifyList, connectionId, connectionInfo, errCode);
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
}

static cJSON *GetLocalInfoJson(int32_t roleType)
{
    cJSON *json =  cJSON_CreateObject();
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot create cJSON object");
        return NULL;
    }
    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        cJSON_Delete(json);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendSelfBasicInfo Get local dev Id failed.");
        return NULL;
    }
    if (!AddStringToJsonObject(json, "devid", udid)) {
        cJSON_Delete(json);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendSelfBasicInfo Cannot add udid to jsonobj");
        return NULL;
    }
    if (!AddNumberToJsonObject(json, "type", roleType)) {
        cJSON_Delete(json);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendSelfBasicInfo Cannot add type to jsonobj");
        return NULL;
    }
    return json;
}

static int32_t SendSelfBasicInfo(uint32_t connId, int32_t roleType)
{
    cJSON *json =  GetLocalInfoJson(roleType);
    if (json == NULL) {
        return SOFTBUS_ERR;
    }
    char *data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "cJSON_PrintUnformatted failed");
        return SOFTBUS_ERR;
    }
    uint32_t dataLen = strlen(data) + 1 + TYPE_HEADER_SIZE;
    int32_t *buf = (int32_t *)SoftBusCalloc(dataLen);
    if (buf == NULL) {
        cJSON_free(data);
        return SOFTBUS_ERR;
    }
    buf[0] = TYPE_BASIC_INFO;
    if (memcpy_s((char*)buf + TYPE_HEADER_SIZE, dataLen - TYPE_HEADER_SIZE, data, strlen(data) + 1)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s data error");
        cJSON_free(data);
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    cJSON_free(data);
    static int i = 0;
    ConnPostData postData = {
        .module = MODULE_BLE_NET,
        .seq = i++,
        .flag = 0,
        .pid = 0,
        .len = dataLen,
        .buf = (char*)buf
    };
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendSelfBasicInfo BlePostBytesInner module:%d", postData.module);
    int ret = BlePostBytesInner(connId, &postData);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendSelfBasicInfo BlePostBytesInner failed");
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_SEND_FAIL);
        SoftBusFree(buf);
    }
    return ret;
}

static int32_t PeerBasicInfoParse(BleConnectionInfo *connInfo, const char *value, int32_t len)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConnectId=%d receive basicInfo data", connInfo->connId);
    if (len <= TYPE_HEADER_SIZE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "PeerBasicInfoParse invalid data length");
        return SOFTBUS_ERR;
    }
    cJSON *data = cJSON_ParseWithLength(value + TYPE_HEADER_SIZE, len - TYPE_HEADER_SIZE);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "PeerBasicInfoParse cJSON_Parse failed");
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectStringItem(data, "devid", connInfo->peerDevId, UUID_BUF_LEN) ||
        !GetJsonObjectNumberItem(data, "type", &connInfo->peerType)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "PeerBasicInfoParse get info failed");
        cJSON_Delete(data);
        return SOFTBUS_ERR;
    }
    cJSON_Delete(data);
    char udidHash[UDID_HASH_LEN];
    if (SoftBusGenerateStrHash((unsigned char *)connInfo->peerDevId, strlen(connInfo->peerDevId),
        (unsigned char *)udidHash) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "PeerBasicInfoParse GenerateStrHash failed");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN, udidHash, UDID_HASH_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "PeerBasicInfoParse memcpy_s failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t BleOnDataUpdate(BleConnectionInfo *targetNode)
{
    if (targetNode->peerType != BLE_ROLE_CLIENT && targetNode->peerType != BLE_ROLE_SERVER) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleOnDataUpdate invalid role type");
        return SOFTBUS_ERR;
    }
    if (targetNode->peerType == BLE_ROLE_SERVER) {
        BleClientDoneConnect(targetNode);
        return SOFTBUS_OK;
    }
    if (SendSelfBasicInfo(targetNode->connId, BLE_ROLE_SERVER) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendSelfBasicInfo error");
        return SOFTBUS_ERR;
    }
    g_connectCallback->OnConnected(targetNode->connId, &(targetNode->info));
    return SOFTBUS_OK;
}

static void BleConnectionReceived(BleHalConnInfo halConnInfo, uint32_t len, const char *value)
{
    uint32_t connPktHeadLen = (uint32_t) sizeof(ConnPktHead);
    if (connPktHeadLen >= len) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleOnConnectionReceived len error");
        return;
    }
    ConnPktHead *head = (ConnPktHead *)value;
    UnpackConnPktHead(head);
    if (UINT32_MAX - connPktHeadLen < head->len || head->len + connPktHeadLen > len) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BLEINFOPRINT: recv broken data:%d, not support",
                   head->len + connPktHeadLen);
        return;
    }
    if (SoftBusMutexLock(&g_connectionLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    BleConnectionInfo *targetNode = GetBleConnInfoByHalConnId(halConnInfo);
    if (targetNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleOnDataReceived unknown device");
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return;
    }
    uint32_t connectionId = targetNode->connId;
    (void)SoftBusMutexUnlock(&g_connectionLock);
    if (head->module != MODULE_CONNECTION) {
        if (g_connectCallback != NULL) {
            g_connectCallback->OnDataReceived(connectionId, (ConnModule) head->module, head->seq,
                (char *)value, head->len + connPktHeadLen);
        }
        return;
    }
    cJSON *data = cJSON_ParseWithLength(value + connPktHeadLen, head->len);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[receive data invalid]");
        return;
    }
    RecvConnectedComd(connectionId, (const cJSON*)data);
    cJSON_Delete(data);
}
static void BleNetReceived(BleHalConnInfo halConnInfo, uint32_t len, const char *value)
{
    if (SoftBusMutexLock(&g_connectionLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    BleConnectionInfo *targetNode = GetBleConnInfoByHalConnId(halConnInfo);
    if (targetNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleOnDataReceived unknown device");
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return;
    }
    if (targetNode->state != BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED) {
        if (PeerBasicInfoParse(targetNode, value, len) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "PeerBasicInfoParse failed");
            (void)SoftBusMutexUnlock(&g_connectionLock);
            return;
        }
        SoftbusGattcOnRecvHandShakeRespon(targetNode->halConnId);
        targetNode->state = BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED;
        if (BleOnDataUpdate(targetNode) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleOnDataUpdate failed");
        }
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return;
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    g_connectCallback->OnDataReceived(targetNode->connId, MODULE_BLE_NET, 0, (char *)value, len);
}

static void BleOnDataReceived(bool isBleConn, BleHalConnInfo halConnInfo, uint32_t len, const char *value)
{
    isBleConn ? BleConnectionReceived(halConnInfo, len, value) : BleNetReceived(halConnInfo, len, value);
}

static int32_t SendBleData(SendQueueNode *node)
{
    if (node->len > MAX_DATA_LEN) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendBleData big msg, len:%u\n", node->len);
    }

    BleConnectionInfo *connInfo = GetBleConnInfoByConnId(node->connectionId);
    if (connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleMtuChangeCallback GetBleConnInfo failed");
        return SOFTBUS_ERR;
    }
    if (node->isInner) {
        return BleTransSend(connInfo, node->data, node->len, node->seq, node->module);
    }
    ConnPktHead *head = (ConnPktHead *)node->data;
    return BleTransSend(connInfo, node->data, node->len, head->seq, head->module);
}

static void FreeSendNode(SendQueueNode *node)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "FreeSendNode");
    if (node == NULL) {
        return;
    }
    if (node->data != NULL) {
        SoftBusFree((void *)node->data);
    }
    SoftBusFree((void *)node);
}

void *BleSendTask(void *arg)
{
#define WAIT_TIME 10
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleSendTask enter");
    SendQueueNode *node = NULL;
    while (1) {
        int32_t ret = BleDequeueBlock((void **)(&node));
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ble dequeue send node failed, error=%d", ret);
            SoftBusSleepMs(WAIT_TIME);
            continue;
        }
        if (SendBleData(node) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendItem fail");
        }
        FreeSendNode(node);
        node = NULL;
    }
}

static void InitBleInterface(void)
{
    g_bleInterface.ConnectDevice = BleConnectDevice;
    g_bleInterface.PostBytes = BlePostBytes;
    g_bleInterface.DisconnectDevice = BleDisconnectDevice;
    g_bleInterface.DisconnectDeviceNow = BleDisconnectDeviceNow;
    g_bleInterface.GetConnectionInfo = BleGetConnectionInfo;
    g_bleInterface.StartLocalListening = BleStartLocalListening;
    g_bleInterface.StopLocalListening = BleStopLocalListening;
    g_bleInterface.CheckActiveConnection = BleCheckActiveConnection;
    g_bleInterface.UpdateConnection = BleUpdateConnection;
}

static int BleQueueInit(void)
{
    if (BleInnerQueueInit() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    SoftBusThread tid;
    if (SoftBusThreadCreate(&tid, NULL, BleSendTask, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create BleSendTask failed");
        BleInnerQueueDeinit();
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void BleConnOnBtStateChanged(int listenerId, int state)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[BleOnBtStateChanged] id:%d, state:%d", listenerId, state);
    SoftBusGattServerOnBtStateChanged(state);
}

static SoftBusBtStateListener g_bleConnStateListener = {
    .OnBtStateChanged = BleConnOnBtStateChanged,
    .OnBtAclStateChanged = NULL,
};

static SoftBusBleConnCalback g_bleClientConnCalback = {
    .BleOnDataReceived = BleOnDataReceived,
    .BleDisconnectCallback = BleDisconnectCallback,
    .BleConnectCallback = BleClientConnectCallback,
    .GetBleConnInfoByHalConnId = GetBleConnInfoByHalConnId,
};

static SoftBusBleConnCalback g_bleServerConnCalback = {
    .BleOnDataReceived = BleOnDataReceived,
    .BleDisconnectCallback = BleDisconnectCallback,
    .BleConnectCallback = BleServerConnectCallback,
    .GetBleConnInfoByHalConnId = GetBleConnInfoByHalConnId,
};

static SoftBusBleTransCalback g_bleTransCallback = {
    .GetBleConnInfoByHalConnId = GetBleConnInfoByHalConnId,
};

static void BleConnectionMsgHandler(SoftBusMessage *msg)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, " 11ble gattc conn loop process msg type %d", msg->what);
    switch (msg->what) {
        case BLE_CONNECTION_DISCONNECT_OUT: {
            uint32_t connectionId = (uint32_t)msg->arg1;
            BleConnectionInfo *targetNode = NULL;
            if (SoftBusMutexLock(&g_connectionLock) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
                return;
            }
            ListNode *item = NULL;
            LIST_FOR_EACH(item, &g_connection_list) {
                BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
                if (itemNode->connId == connectionId) {
                    targetNode = itemNode;
                    break;
                }
            }
            if (targetNode == NULL) {
                (void)SoftBusMutexUnlock(&g_connectionLock);
                return;
            }
            AbortConnection(targetNode->btBinaryAddr, targetNode->halConnId, targetNode->info.isServer);
            (void)SoftBusMutexUnlock(&g_connectionLock);
            break;
        }
        default:
            break;
    }
}

static int32_t BleConnectionRemoveMessageFunc(const SoftBusMessage *msg, void *args)
{
    uint64_t clientId = (uint64_t)(uintptr_t)args;
    if ((msg->what == BLE_CONNECTION_DISCONNECT_OUT) && (msg->arg1 == clientId)) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

static int BleConnLooperInit(void)
{
    g_bleConnectAsyncHandler.name = (char *)"ble_conn_handler";
    g_bleConnectAsyncHandler.HandleMessage = BleConnectionMsgHandler;
    g_bleConnectAsyncHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_bleConnectAsyncHandler.looper == NULL ||
        g_bleConnectAsyncHandler.looper->PostMessage == NULL ||
        g_bleConnectAsyncHandler.looper->PostMessageDelay == NULL ||
        g_bleConnectAsyncHandler.looper->RemoveMessageCustom == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create looper failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

ConnectFuncInterface *ConnInitBle(const ConnectCallback *callback)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[InitBle]");
    int32_t ret;
    ret = BleConnLooperInit();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleConnLooperInit failed: %d", ret);
        return NULL;
    }
    ret = SoftBusGattServerInit(&g_bleServerConnCalback);
    if (ret != SOFTBUS_OK) {
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_GATTSERVER_INIT_FAIL);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusGattServerInit failed: %d", ret);
        return NULL;
    }
    ret = SoftBusGattClientInit(&g_bleClientConnCalback);
    if (ret != SOFTBUS_OK) {
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_GATTCLIENT_INIT_FAIL);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusGattClientInit failed: %d", ret);
        return NULL;
    }
    ret = BleTransInit(&g_bleTransCallback);
    if (ret != SOFTBUS_OK) {
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_TRANS_INIT_FAIL);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransInit failed: %d", ret);
        return NULL;
    }
    SoftBusMutexAttr attr;
    attr.type = SOFTBUS_MUTEX_RECURSIVE;
    SoftBusMutexInit(&g_connectionLock, &attr);
    ret = BleQueueInit();
    if (ret != SOFTBUS_OK) {
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_QUEUE_INIT_FAIL);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleQueueInit failed: %d", ret);
        return NULL;
    }
    ret = SoftBusAddBtStateListener(&g_bleConnStateListener);
    if (ret < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusAddBtStateListener failed: %d", ret);
        return NULL;
    }
    g_connectCallback = (ConnectCallback*)callback;
    InitBleInterface();
    SoftBusRegConnVarDump(BLE_CONNECTION_INFO, &BleConnectionDump);
    return &g_bleInterface;
}

static int32_t BleConnectionDump(int fd)
{
    char addr[BT_ADDR_LEN] = {0};
    char bleMac[BT_MAC_LEN] = {0};
    char deviceIdHash[UDID_HASH_LEN] = {0};
    char peerDevId[UDID_BUF_LEN] = {0};
    if (SoftBusMutexLock(&g_connectionLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }
    ListNode *item = NULL;
    SOFTBUS_DPRINTF(fd, "\n-----------------BLEConnectList Info-------------------\n");
    LIST_FOR_EACH(item, &g_connection_list) {
        BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        SOFTBUS_DPRINTF(fd, "halConnId                     : %d\n", itemNode->halConnId);
        SOFTBUS_DPRINTF(fd, "connId                        : %d\n", itemNode->connId);
        DataMasking((char *)(itemNode->btBinaryAddr.addr), BT_ADDR_LEN, MAC_DELIMITER, addr);
        SOFTBUS_DPRINTF(fd, "btMac                         : %s\n", addr);
        SOFTBUS_DPRINTF(fd, "Connection Info isAvailable   : %d\n", itemNode->info.isAvailable);
        SOFTBUS_DPRINTF(fd, "Connection Info isServer      : %d\n", itemNode->info.isServer);
        SOFTBUS_DPRINTF(fd, "Connection Info type          : %u\n", itemNode->info.type);
        DataMasking(itemNode->info.bleInfo.bleMac, BT_MAC_LEN, MAC_DELIMITER, bleMac);
        SOFTBUS_DPRINTF(fd, "BleInfo addr                  : %s\n", bleMac);
        DataMasking(itemNode->info.bleInfo.deviceIdHash, UDID_HASH_LEN, ID_DELIMITER, deviceIdHash);
        SOFTBUS_DPRINTF(fd, "BleInfo deviceIdHash          : %s\n", deviceIdHash);
        SOFTBUS_DPRINTF(fd, "Connection state              : %d\n", itemNode->state);
        SOFTBUS_DPRINTF(fd, "Connection refCount           : %d\n", itemNode->refCount);
        SOFTBUS_DPRINTF(fd, "Connection mtu                : %d\n", itemNode->mtu);
        SOFTBUS_DPRINTF(fd, "Connection peerType           : %d\n", itemNode->peerType);
        DataMasking(itemNode->peerDevId, UDID_BUF_LEN, ID_DELIMITER, peerDevId);
        SOFTBUS_DPRINTF(fd, "Connection peerDevId          : %s\n", peerDevId);
        LIST_FOR_EACH(item, &itemNode->requestList) {
            BleRequestInfo *requestNode = LIST_ENTRY(item, BleRequestInfo, node);
            SOFTBUS_DPRINTF(fd, "request isUsed                : %u\n", requestNode->requestId);
        }
        for (int i = 0; i < MAX_CACHE_NUM_PER_CONN; i++) {
            SOFTBUS_DPRINTF(fd, "recvCache isUsed              : %d\n", itemNode->recvCache[i].isUsed);
            SOFTBUS_DPRINTF(fd, "recvCache timeStamp           : %d\n", itemNode->recvCache[i].timeStamp);
            SOFTBUS_DPRINTF(fd, "recvCache seq                 : %d\n", itemNode->recvCache[i].seq);
            SOFTBUS_DPRINTF(fd, "recvCache currentSize         : %d\n", itemNode->recvCache[i].currentSize);
            SOFTBUS_DPRINTF(fd, "recvCache cache               : %s\n", itemNode->recvCache[i].cache);
        }
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    return SOFTBUS_OK;
}
