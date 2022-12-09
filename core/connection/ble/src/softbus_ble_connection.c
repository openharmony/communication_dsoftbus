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

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>

#include "bus_center_manager.h"
#include "cJSON.h"
#include "common_list.h"
#include "securec.h"
#include "softbus_adapter_ble_gatt_server.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_ble_gatt_client.h"
#include "softbus_ble_gatt_server.h"
#include "softbus_ble_queue.h"
#include "softbus_ble_trans_manager.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_queue.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"

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

typedef struct {
    int32_t type;
} BleBasicInfo;

static const int BLE_GATT_ATT_MTU_DEFAULT_PAYLOAD = 21;
static const int BLE_GATT_ATT_MTU_MAX = 512;
static const int BLE_ROLE_CLIENT = 1;
static const int BLE_ROLE_SERVER = 2;

static LIST_HEAD(g_connection_list);
static ConnectCallback *g_connectCallback = NULL;
static ConnectFuncInterface g_bleInterface = { 0 };
static SoftBusMutex g_connectionLock;

static void PackRequest(int32_t delta, uint32_t connectionId);
static int32_t SendSelfBasicInfo(uint32_t connId, int32_t roleType);

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
    BleConnectionInfo *newConnectionInfo = SoftBusCalloc(sizeof(BleConnectionInfo));
    if (newConnectionInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ConnectDeviceFristTime malloc fail.]");
        return NULL;
    }
    ListInit(&newConnectionInfo->node);
    ListInit(&newConnectionInfo->requestList);
    newConnectionInfo->connId = AllocBleConnectionIdLocked();
    newConnectionInfo->mtu = BLE_GATT_ATT_MTU_DEFAULT_PAYLOAD;
    newConnectionInfo->refCount = 1;
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

BleConnectionInfo* GetBleConnInfoByHalConnId(int32_t halConnectionId)
{
    ListNode *item = NULL;
    BleConnectionInfo *itemNode = NULL;
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    LIST_FOR_EACH(item, &g_connection_list) {
        itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->halConnId == halConnectionId) {
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
        if (memcmp(itemNode->info.info.bleInfo.bleMac, strAddr, BT_MAC_LEN) == 0) {
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
    if (strcpy_s(connectionInfo.info.bleInfo.bleMac, BT_MAC_LEN, itemNode->info.info.bleInfo.bleMac) != EOK) {
        return;
    }
    int connectionId = itemNode->connId;

    (void)SoftBusMutexUnlock(&g_connectionLock);
    if (result->OnConnectSuccessed != NULL) {
        result->OnConnectSuccessed(
            requestId, connectionId, &connectionInfo);
    }

    (void)PackRequest(CONNECT_REF_INCRESE, connectionId);
}

static int32_t BleConnectDeviceFristTime(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    BleConnectionInfo *newConnectionInfo = CreateBleConnectionNode();
    if (newConnectionInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ble client node create fail");
        return SOFTBUS_ERR;
    }
    BleRequestInfo *requestInfo = SoftBusCalloc(sizeof(BleRequestInfo));
    if (requestInfo == NULL) {
        ReleaseBleconnectionNode(newConnectionInfo);
        return SOFTBUS_ERR;
    }
    newConnectionInfo->mtu = BLE_GATT_ATT_MTU_MAX;
    ListInit(&requestInfo->node);
    ListAdd(&newConnectionInfo->requestList, &requestInfo->node);
    if (strcpy_s(newConnectionInfo->info.info.bleInfo.bleMac, BT_MAC_LEN,
        option->info.bleOption.bleMac) != EOK) {
        ReleaseBleconnectionNode(newConnectionInfo);
        return SOFTBUS_ERR;
    }
    char tempBleMac[BT_MAC_LEN];
    if (strcpy_s(tempBleMac, BT_MAC_LEN, option->info.bleOption.bleMac) != EOK) {
        ReleaseBleconnectionNode(newConnectionInfo);
        return SOFTBUS_ERR;
    }
    requestInfo->requestId = requestId;
    (void)memcpy_s(&requestInfo->callback, sizeof(requestInfo->callback), result, sizeof(*result));
    newConnectionInfo->state = BLE_CONNECTION_STATE_CONNECTING;
    newConnectionInfo->info.isServer = BLE_CLIENT_TYPE;
    int32_t clientId = INVALID_CLIENID;
    if (ConvertBtMacToBinary(tempBleMac, BT_MAC_LEN,
        newConnectionInfo->btBinaryAddr.addr, BT_ADDR_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "convert bt mac to binary fail.");
        ReleaseBleconnectionNode(newConnectionInfo);
        return SOFTBUS_ERR;
    }
    clientId = SoftBusGattClientConnect(&(newConnectionInfo->btBinaryAddr));
    if (clientId < 0) {
        ReleaseBleconnectionNode(newConnectionInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusGattClientConnect fail ret=%d", clientId);
        return SOFTBUS_ERR;
    }
    newConnectionInfo->halConnId = clientId;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "new connection %d,clientId=%d",
        newConnectionInfo->connId, clientId);
    ListAdd(&g_connection_list, &newConnectionInfo->node);
    return SOFTBUS_OK;
}

static int32_t BleConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
        "BleConnectDevice, requestId=%d", requestId);
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    int32_t ret = SOFTBUS_OK;
    ListNode *item = NULL;
    BleConnectionInfo *targetConnectionInfo = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->info.isServer != BLE_CLIENT_TYPE) {
            continue;
        }
        if (strcmp(itemNode->info.info.bleInfo.bleMac, option->info.bleOption.bleMac) == 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[state = %d]", itemNode->state);
            targetConnectionInfo = itemNode;
            if (itemNode->state == BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED) {
                BleDeviceConnected(itemNode, requestId, result);
                (void)SoftBusMutexUnlock(&g_connectionLock);
                return SOFTBUS_OK;
            } else if (itemNode->state == BLE_CONNECTION_STATE_CONNECTING ||
                itemNode->state == BLE_CONNECTION_STATE_CONNECTED) {
                BleRequestInfo *requestInfo = SoftBusMalloc(sizeof(BleRequestInfo));
                if (requestInfo == NULL) {
                    (void)SoftBusMutexUnlock(&g_connectionLock);
                    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "malloc failed");
                    return SOFTBUS_ERR;
                }
                (void)memset_s(requestInfo, sizeof(BleRequestInfo), 0, sizeof(BleRequestInfo));
                ListInit(&requestInfo->node);
                requestInfo->requestId = requestId;
                (void)memcpy_s(&requestInfo->callback, sizeof(requestInfo->callback), result, sizeof(*result));
                ListAdd(&itemNode->requestList, &requestInfo->node);
                (void)SoftBusMutexUnlock(&g_connectionLock);
                return SOFTBUS_OK;
            } else if (itemNode->state == BLE_CONNECTION_STATE_CLOSING) {
                result->OnConnectFailed(requestId, 0);
                (void)SoftBusMutexUnlock(&g_connectionLock);
                return SOFTBUS_OK;
            }
        }
    }
    if (targetConnectionInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[targetConnectionInfo == NULL]");
        ret = BleConnectDeviceFristTime(option, requestId, result);
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
    return ret;
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
        SoftBusFree((void *)data);
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return SOFTBUS_BLECONNECTION_GETCONNINFO_ERROR;
    }
    SendQueueNode *node = SoftBusCalloc(sizeof(SendQueueNode));
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
    SendQueueNode *node = SoftBusCalloc(sizeof(SendQueueNode));
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
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendRefMessage:%s", data);
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
    ret = GetBleConnInfoByAddr(option->info.bleOption.bleMac, &server, &client);
    if ((ret != SOFTBUS_OK) || ((server == NULL) && (client == NULL))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleDisconnectDevice GetBleConnInfo failed");
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return SOFTBUS_BLECONNECTION_GETCONNINFO_ERROR;
    }
    if (server != NULL) {
        server->state = BLE_CONNECTION_STATE_CLOSING;
        SoftBusGattsDisconnect(server->btBinaryAddr, server->halConnId);
    } else {
        client->state = BLE_CONNECTION_STATE_CLOSING;
        SoftBusGattClientDisconnect(client->halConnId);
    }
    (void)SoftBusMutexUnlock(&g_connectionLock);
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
    ret = GetBleConnInfoByAddr(option->info.bleOption.bleMac, &server, &client);
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

static void BleDeviceConnectPackRequest(int32_t value, int32_t connId)
{
    int32_t data = value;
    while (--data > 0) {
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
    if (memcpy_s(newNode->info.info.bleInfo.bleMac, BT_MAC_LEN, bleStrMac, BT_MAC_LEN) != EOK) {
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
    ConnectionInfo connectionInfo, int32_t value)
{
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    if (IsListEmpty(notifyList) != true) {
        LIST_FOR_EACH_SAFE(item, itemNext, notifyList) {
            BleRequestInfo *requestInfo = LIST_ENTRY(item, BleRequestInfo, node);
            if (requestInfo->callback.OnConnectFailed != NULL) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[BleNotifyDisconnect]connectionId=%d", connectionId);
                requestInfo->callback.OnConnectFailed(requestInfo->requestId, value);
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

static void BleDisconnectCallback(int32_t halConnId, int32_t isServer)
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
        if (itemNode->halConnId == halConnId && itemNode->info.isServer == isServer) {
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
        BleNotifyDisconnect(&notifyList, connectionId, connectionInfo, isServer);
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
    char devId[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, devId, UDID_BUF_LEN) != SOFTBUS_OK) {
        cJSON_Delete(json);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendSelfBasicInfo Get local dev Id failed.");
        return NULL;
    }
    if (!AddStringToJsonObject(json, "devid", devId)) {
        cJSON_Delete(json);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendSelfBasicInfo Cannot add devid to jsonobj");
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
        SoftBusFree(buf);
    }
    return ret;
}

static int32_t PeerBasicInfoParse(BleConnectionInfo *connInfo, const char *value, int32_t len)
{
    if (len <= TYPE_HEADER_SIZE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid data length");
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

static void BleConnectionReceived(BleConnectionInfo *targetNode, uint32_t len, const char *value)
{
    uint32_t connPktHeadLen = (uint32_t) sizeof(ConnPktHead);
    if (connPktHeadLen >= len) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleOnConnectionReceived len error");
        return;
    }
    ConnPktHead *head = (ConnPktHead *)value;
    if (UINT32_MAX - connPktHeadLen < head->len || head->len + connPktHeadLen > len) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BLEINFOPRINT: recv broken data:%d, not support",
                   head->len + connPktHeadLen);
        return;
    }
    if (head->module != MODULE_CONNECTION) {
        if (g_connectCallback != NULL) {
            g_connectCallback->OnDataReceived(targetNode->connId, (ConnModule) head->module, head->seq,
                (char *)value, head->len + connPktHeadLen);
        }
        return;
    }
    cJSON *data = cJSON_ParseWithLength(value + connPktHeadLen, head->len);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[receive data invalid]");
        return;
    }
    RecvConnectedComd(targetNode->connId, (const cJSON*)data);
    cJSON_Delete(data);
}
static void BleNetReceived(BleConnectionInfo *targetNode, uint32_t len, const char *value)
{
    if (targetNode->state != BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED) {
        if (PeerBasicInfoParse(targetNode, value, len) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "PeerBasicInfoParse failed");
            return;
        }
        targetNode->state = BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED;
        if (BleOnDataUpdate(targetNode) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleOnDataUpdate failed");
        }
        return;
    }
    g_connectCallback->OnDataReceived(targetNode->connId, MODULE_BLE_NET, 0, (char *)value, len);
}

static void BleOnDataReceived(bool isBleConn, int32_t halConnId, uint32_t len, const char *value)
{
    if (SoftBusMutexLock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    BleConnectionInfo *targetNode = GetBleConnInfoByHalConnId(halConnId);
    if (targetNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleOnDataReceived unknown device");
        (void)SoftBusMutexUnlock(&g_connectionLock);
        return;
    }
    isBleConn ? BleConnectionReceived(targetNode, len, value) : BleNetReceived(targetNode, len, value);
    (void)SoftBusMutexUnlock(&g_connectionLock);
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
    while (1) {
        SendQueueNode *node = NULL;
        if (BleDequeueNonBlock((void **)(&node)) != SOFTBUS_OK) {
            SoftBusSleepMs(WAIT_TIME);
            continue;
        }
        if (SendBleData(node) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendItem fail");
        }
        FreeSendNode(node);
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
    .OnBtStateChanged = BleConnOnBtStateChanged
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

ConnectFuncInterface *ConnInitBle(const ConnectCallback *callback)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[InitBle]");
    int32_t ret;
    ret = SoftBusGattServerInit(&g_bleServerConnCalback);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusGattServerInit failed: %d", ret);
        return NULL;
    }
    ret = SoftBusGattClientInit(&g_bleClientConnCalback);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusGattClientInit failed: %d", ret);
        return NULL;
    }
    ret = BleTransInit(&g_bleTransCallback);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransInit failed: %d", ret);
        return NULL;
    }
    SoftBusMutexAttr attr;
    attr.type = SOFTBUS_MUTEX_RECURSIVE;
    SoftBusMutexInit(&g_connectionLock, &attr);
    ret = BleQueueInit();
    if (ret != SOFTBUS_OK) {
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
    return &g_bleInterface;
}
