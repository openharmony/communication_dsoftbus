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

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include "time.h"

#include "bus_center_manager.h"
#include "cJSON.h"
#include "common_list.h"
#include "message_handler.h"
#include "securec.h"
#include "softbus_adapter_ble_gatt_server.h"
#include "softbus_adapter_mem.h"
#include "softbus_ble_trans_manager.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_property.h"
#include "softbus_queue.h"
#include "softbus_type_def.h"

#define SEND_QUEUE_UNIT_NUM 128
#define CONNECT_REF_INCRESE 1
#define CONNECT_REF_DECRESE (-1)
#define METHOD_NOTIFY_REQUEST 1
#define METHOD_NOTIFY_RESPONSE 2
#define METHOD_SHUT_DOWN 3
#define CONN_MAGIC_NUMBER  0xBABEFACE
#define KEY_METHOD "KEY_METHOD"
#define KEY_DELTA "KEY_DELTA"
#define KEY_REFERENCE_NUM "KEY_REFERENCE_NUM"
#define TYPE_HEADER_SIZE 4

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
    BLE_CONNECTION_STATE_CONNECTING = 0,
    BLE_CONNECTION_STATE_CONNECTED,
    BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED,
    BLE_CONNECTION_STATE_CLOSING,
    BLE_CONNECTION_STATE_CLOSED
} BleConnectionState;

typedef enum {
    ADD_SERVICE_MSG,
    ADD_CHARA_MSG,
    ADD_DESCRIPTOR_MSG,
} BleConnLoopMsg;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    LockFreeQueue *queue;
} BleQueue;

typedef struct {
    uint32_t halConnId;
    uint32_t connectionId;
    int32_t pid;
    int32_t flag;
    int32_t isServer;
    int32_t isInner;
    int32_t module;
    int32_t seq;
    int32_t len;
    const char *data;
} SendQueueNode;

typedef enum {
    TYPE_UNKNOW = -1,
    TYPE_AUTH = 0,
    TYPE_BASIC_INFO = 1,
    TYPE_DEV_INFO = 2,
} BleNetMsgType;

typedef struct {
    int32_t type;
} BleBasicInfo;

static const int MAX_SERVICE_CHAR_NUM = 8;
static const int BLE_GATT_ATT_MTU_DEFAULT = 23;
static const int BLE_GATT_ATT_MTU_DEFAULT_PAYLOAD = 21;
static const int MTU_HEADER_SIZE = 3;
static const int BLE_GATT_ATT_MTU_MAX = 512;
static const int BLE_ROLE_CLIENT = 1;
static const int BLE_ROLE_SERVER = 2;

static const char *SOFTBUS_SERVICE_UUID = "11C8B310-80E4-4276-AFC0-F81590B2177F";
static const char *SOFTBUS_CHARA_BLENET_UUID = "00002B00-0000-1000-8000-00805F9B34FB";
static const char *SOFTBUS_CHARA_BLECONN_UUID = "00002B01-0000-1000-8000-00805F9B34FB";
static const char *SOFTBUS_DESCRIPTOR_CONFIGURE_UUID = "00002902-0000-1000-8000-00805F9B34FB";

static LIST_HEAD(g_conection_list);
static ConnectCallback *g_connectCallback = NULL;
static SoftBusHandler g_bleAsyncHandler = {
    .name ="g_bleAsyncHandler"
};
static ConnectFuncInterface g_bleInterface = { 0 };
static SoftBusGattsCallback g_bleGattsCallback = { 0 };
static pthread_mutex_t g_connectionLock;
static SoftBusGattService g_gattService = {
    .state = BLE_GATT_SERVICE_INITIAL,
    .svcId = -1,
    .bleConnCharaId = -1,
    .bleConnDesId = -1,
    .bleNetCharaId = -1,
    .bleNetDesId = -1
};
static BleQueue g_sendQueue;

static int32_t ConvertBtMacToBinary(const char *strMac, int32_t strMacLen,
    uint8_t *binMac, int32_t binMacLen)
{
    int32_t ret;

    if (strMac == NULL || strMacLen < BT_MAC_LEN || binMac == NULL || binMacLen < BT_ADDR_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    ret = sscanf_s(strMac, "%02x:%02x:%02x:%02x:%02x:%02x",
        &binMac[0], &binMac[1], &binMac[2], &binMac[3], &binMac[4], &binMac[5]);
    if (ret < 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConvertBtMacToStr(char *strMac, int32_t strMacLen,
    const uint8_t *binMac, int32_t binMacLen)
{
    int32_t ret;

    if (strMac == NULL || strMacLen < BT_MAC_LEN || binMac == NULL || binMacLen < BT_ADDR_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    ret = snprintf_s(strMac, strMacLen, strMacLen - 1, "%02x:%02x:%02x:%02x:%02x:%02x",
        binMac[0], binMac[1], binMac[2], binMac[3], binMac[4], binMac[5]);
    if (ret < 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static SoftBusMessage *BleConnCreateLoopMsg(int32_t what, uint64_t arg1, uint64_t arg2, const char *data)
{
    SoftBusMessage *msg = NULL;
    msg = SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleConnCreateLoopMsg SoftBusCalloc failed");
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

static int32_t AllocBleConnectionIdLocked()
{
    static int16_t nextConnectionId = 0;
    uint32_t tempId;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return 0;
    }
    nextConnectionId++;
    while (1) {
        tempId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + nextConnectionId;
        ListNode *item = NULL;
        LIST_FOR_EACH(item, &g_conection_list) {
            BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
            if (itemNode->connId == tempId) {
                nextConnectionId++;
                continue;
            }
        }
        break;
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
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
    newConnectionInfo->connId = AllocBleConnectionIdLocked();
    newConnectionInfo->mtu = BLE_GATT_ATT_MTU_DEFAULT_PAYLOAD;
    newConnectionInfo->refCount = 1;
    newConnectionInfo->info.isAvailable = 1;
    newConnectionInfo->info.type = CONNECT_BLE;
    return newConnectionInfo;
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
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    LIST_FOR_EACH(item, &g_conection_list) {
        itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->connId == connectionId) {
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return itemNode;
}

BleConnectionInfo* GetBleConnInfoByHalConnId(int32_t halConnectionId)
{
    ListNode *item = NULL;
    BleConnectionInfo *itemNode = NULL;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    LIST_FOR_EACH(item, &g_conection_list) {
        itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->halConnId == halConnectionId) {
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return itemNode;
}

static int32_t GetBleConnInfoByAddr(const char *strAddr, BleConnectionInfo **server, BleConnectionInfo **client)
{
    ListNode *item = NULL;
    BleConnectionInfo *itemNode = NULL;
    bool findServer = false;
    bool findClient = false;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_BLECONNECTION_MUTEX_LOCK_ERROR;
    }
    LIST_FOR_EACH(item, &g_conection_list) {
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
    (void)pthread_mutex_unlock(&g_connectionLock);
    return SOFTBUS_OK;
}

int32_t GetBleAttrHandle(int32_t module)
{
    return (module == MODULE_BLE_NET) ? g_gattService.bleNetCharaId : g_gattService.bleConnCharaId;
}

static int32_t BleConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
        "ConnectDevice failed, reason:gatt client is not currently supported");
    return SOFTBUS_BLECONNECTION_GATT_CLIENT_NOT_SUPPORT;
}

static int BleEnqueueNonBlock(const void *msg)
{
    if (msg == NULL) {
        return SOFTBUS_ERR;
    }
    return QueueMultiProducerEnqueue(g_sendQueue.queue, msg);
}

static int BleDequeueBlock(void **msg)
{
    if (msg == NULL) {
        return SOFTBUS_ERR;
    }
    if (QueueSingleConsumerDequeue(g_sendQueue.queue, msg) == 0) {
        return SOFTBUS_OK;
    }
    (void)pthread_mutex_lock(&g_sendQueue.lock);
    if (QueueIsEmpty(g_sendQueue.queue) == 0) {
        pthread_cond_wait(&g_sendQueue.cond, &g_sendQueue.lock);
        (void)pthread_mutex_unlock(&g_sendQueue.lock);
    }
    return QueueSingleConsumerDequeue(g_sendQueue.queue, msg);
}

static int32_t BlePostBytes(uint32_t connectionId, const char *data, int32_t len, int32_t pid, int32_t flag)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "BlePostBytes connectionId=%u,pid=%d,len=%d flag=%d", connectionId, pid, len, flag);
    if (data == NULL) {
        return SOFTBUS_ERR;
    }
    BleConnectionInfo *connInfo = GetBleConnInfoByConnId(connectionId);
    if (connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BlePostBytes GetBleConnInfo failed");
        return SOFTBUS_BLECONNECTION_GETCONNINFO_ERROR;
    }
    SendQueueNode *node = SoftBusCalloc(sizeof(SendQueueNode));
    if (node == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    node->halConnId = connInfo->halConnId;
    node->connectionId = connectionId;
    node->isServer = connInfo->info.isServer;
    node->pid = pid;
    node->flag = flag;
    node->len = len;
    node->data = data;
    int ret = BleEnqueueNonBlock((const void *)node);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BlePostBytes enqueue failed");
        SoftBusFree(node);
        return ret;
    }
    (void)pthread_mutex_lock(&g_sendQueue.lock);
    pthread_cond_signal(&g_sendQueue.cond);
    (void)pthread_mutex_unlock(&g_sendQueue.lock);
    return SOFTBUS_OK;
}

static int32_t BlePostBytesInner(uint32_t connectionId, ConnPostData *data)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BlePostBytesInner connectionId=%u", connectionId);
    if (data == NULL) {
        return SOFTBUS_ERR;
    }
    BleConnectionInfo *connInfo = GetBleConnInfoByConnId(connectionId);
    if (connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BlePostBytes GetBleConnInfo failed");
        return SOFTBUS_BLECONNECTION_GETCONNINFO_ERROR;
    }
    SendQueueNode *node = SoftBusCalloc(sizeof(SendQueueNode));
    if (node == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    node->halConnId = connInfo->halConnId;
    node->connectionId = connectionId;
    node->isServer = connInfo->info.isServer;
    node->len = data->len;
    node->data = data->buf;
    node->isInner = 1;
    node->module = data->module;
    node->isInner = data->seq;
    int ret = BleEnqueueNonBlock((const void *)node);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BlePostBytes enqueue failed");
        SoftBusFree(node);
        return ret;
    }
    (void)pthread_mutex_lock(&g_sendQueue.lock);
    pthread_cond_signal(&g_sendQueue.cond);
    (void)pthread_mutex_unlock(&g_sendQueue.lock);
    return SOFTBUS_OK;
}

static int AddNumToJson(cJSON *json, int32_t requestOrResponse, int32_t delta, int32_t count)
{
    if (requestOrResponse == METHOD_NOTIFY_REQUEST) {
        if (!AddNumberToJsonObject(json, KEY_METHOD, METHOD_NOTIFY_REQUEST) ||
            !AddNumberToJsonObject(json, KEY_DELTA, delta) ||
            !AddNumberToJsonObject(json, KEY_REFERENCE_NUM, count)) {
            return SOFTBUS_BRCONNECTION_PACKJSON_ERROR;
        }
    } else {
        if (!AddNumberToJsonObject(json, KEY_METHOD, METHOD_NOTIFY_RESPONSE) ||
            !AddNumberToJsonObject(json, KEY_REFERENCE_NUM, count)) {
            return SOFTBUS_BRCONNECTION_PACKJSON_ERROR;
        }
    }
    return SOFTBUS_OK;
}

static void SendRefMessage(int32_t delta, int32_t connectionId, int32_t count, int32_t requestOrResponse)
{
    cJSON *json =  cJSON_CreateObject();
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

    int32_t headSize = sizeof(ConnPktHead);
    int32_t dataLen = strlen(data) + 1 + headSize;
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

    if (memcpy_s(buf, dataLen, (void *)&head, headSize)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s head error");
        cJSON_free(data);
        SoftBusFree(buf);
        return;
    }
    if (memcpy_s(buf + headSize, dataLen - headSize, data, strlen(data) + 1)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s data error");
        cJSON_free(data);
        SoftBusFree(buf);
        return;
    }
    cJSON_free(data);
    if (BlePostBytes(connectionId, buf, dataLen, 0, 0) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendRefMessage BlePostBytes failed");
        SoftBusFree(buf);
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
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    LIST_FOR_EACH(item, &g_conection_list) {
        BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->connId == connectionId) {
            itemNode->refCount += delta;
            refCount = itemNode->refCount;
            targetNode = itemNode;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    if (targetNode == NULL) {
        return;
    }

    SendRefMessage(delta, connectionId, refCount, METHOD_NOTIFY_REQUEST);
}

static void OnPackResponse(int32_t delta, int32_t peerRef, uint32_t connectionId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "[onNotifyRequest: delta=%d, RemoteRef=%d, connectionIds=%u", delta, peerRef, connectionId);
    ListNode *item = NULL;
    BleConnectionInfo *targetNode = NULL;
    int myRefCount;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    LIST_FOR_EACH(item, &g_conection_list) {
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
        (void)pthread_mutex_unlock(&g_connectionLock);
        return;
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[onPackRequest: myRefCount=%d]", myRefCount);
    if (peerRef > 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[remote device Ref is > 0, do not reply]");
        return;
    }
    if (myRefCount <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[local device Ref <= 0, close connection now]");
        SoftBusGattsDisconnect(targetNode->btBinaryAddr, targetNode->halConnId);
        return;
    }
    SendRefMessage(delta, connectionId, myRefCount, METHOD_NOTIFY_RESPONSE);
}

static void RecvConnectedComd(uint32_t connectionId, const cJSON *data)
{
    int32_t keyMethod = 0;
    int32_t keyDelta = 0;
    int32_t keyRefernceNum = 0;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RecvConnectedComd ID=%u", connectionId);

    if (!GetJsonObjectNumberItem(data, KEY_METHOD, &keyMethod)) {
        return;
    }
    if (keyMethod == METHOD_NOTIFY_REQUEST) {
        if (!GetJsonObjectNumberItem(data, KEY_METHOD, &keyMethod) ||
            !GetJsonObjectNumberItem(data, KEY_DELTA, &keyDelta) ||
            !GetJsonObjectNumberItem(data, KEY_REFERENCE_NUM, &keyRefernceNum)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "REQUEST fail");
            return;
        }
        OnPackResponse(keyDelta, keyRefernceNum, connectionId);
    }
    if (keyMethod == METHOD_NOTIFY_RESPONSE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "NOTIFY_RESPONSE");
        if (!GetJsonObjectNumberItem(data, KEY_METHOD, &keyMethod) ||
            !GetJsonObjectNumberItem(data, KEY_REFERENCE_NUM, &keyRefernceNum)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RESPONSE fail");
            return;
        }
        (void)pthread_mutex_lock(&g_connectionLock);
        ListNode *item = NULL;
        LIST_FOR_EACH(item, &g_conection_list) {
            BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
            if (itemNode->connId == connectionId) {
                if (itemNode->state == BLE_CONNECTION_STATE_CLOSING) {
                    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "NOTIFY_CHANGE");
                    itemNode->state = BLE_CONNECTION_STATE_CONNECTED;
                }
                break;
            }
        }
        (void)pthread_mutex_unlock(&g_connectionLock);
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
    ret = GetBleConnInfoByAddr(option->info.bleOption.bleMac, &server, &client);
    if ((ret != SOFTBUS_OK) || ((server == NULL) && (client == NULL))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleDisconnectDevice GetBleConnInfo failed");
        return SOFTBUS_BLECONNECTION_GETCONNINFO_ERROR;
    }
    SoftBusBtAddr btAddr;
    if (server != NULL) {
        ret = ConvertBtMacToBinary((const char *)server->info.info.bleInfo.bleMac,
            BT_MAC_LEN, btAddr.addr, BT_ADDR_LEN);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Convert ble addr to binary failed:%d", ret);
            return ret;
        }
        ret = SoftBusGattsDisconnect(btAddr, server->halConnId);
    } else {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
            "BleDisconnectDeviceNow failed, reason:gatt client not support");
        return SOFTBUS_BLECONNECTION_GATT_CLIENT_NOT_SUPPORT;
    }
    return ret;
}

static int32_t BleGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    int32_t result = SOFTBUS_ERR;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_conection_list) {
        BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->connId == connectionId) {
            if (memcpy_s(info, sizeof(ConnectionInfo), &(itemNode->info), sizeof(ConnectionInfo)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGetConnInfo scpy error");
                (void)pthread_mutex_unlock(&g_connectionLock);
                return SOFTBUS_BLECONNECTION_GETCONNINFO_ERROR;
            }
            result = SOFTBUS_OK;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return result;
}

static int32_t BleStartLocalListening(const LocalListenerInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleGattsStartService enter");
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_BLECONNECTION_MUTEX_LOCK_ERROR;
    }
    if ((g_gattService.state == BLE_GATT_SERVICE_STARTED) ||
        (g_gattService.state == BLE_GATT_SERVICE_STARTING)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
            "BleStartLocalListening service already started or is starting");
        (void)pthread_mutex_unlock(&g_connectionLock);
        return SOFTBUS_OK;
    }
    if (g_gattService.state == BLE_GATT_SERVICE_ADDED) {
        g_gattService.state = BLE_GATT_SERVICE_STARTING;
        int ret = SoftBusGattsStartService(g_gattService.svcId);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusGattsStartService failed");
            g_gattService.state = BLE_GATT_SERVICE_ADDED;
        }
        (void)pthread_mutex_unlock(&g_connectionLock);
        return (ret == SOFTBUS_OK) ? ret : SOFTBUS_ERR;
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
        "BleStartLocalListening wrong service state:%d", g_gattService.state);
    return SOFTBUS_ERR;
}

static int32_t BleStopLocalListening(const LocalListenerInfo *info)
{
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_BLECONNECTION_MUTEX_LOCK_ERROR;
    }
    if ((g_gattService.state == BLE_GATT_SERVICE_ADDED) ||
        (g_gattService.state == BLE_GATT_SERVICE_STOPPING)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
            "BleStopLocalListening service already stopped or is stopping");
        (void)pthread_mutex_unlock(&g_connectionLock);
        return SOFTBUS_OK;
    }
    if (g_gattService.state == BLE_GATT_SERVICE_STARTED) {
        g_gattService.state = BLE_GATT_SERVICE_STOPPING;
        int ret = SoftBusGattsStopService(g_gattService.svcId);
        if (ret != SOFTBUS_OK) {
            g_gattService.state = BLE_GATT_SERVICE_STARTED;
        }
        (void)pthread_mutex_unlock(&g_connectionLock);
        return (ret == SOFTBUS_OK) ? ret : SOFTBUS_ERR;
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
        "BleStopLocalListening wrong service state:%d", g_gattService.state);
    return SOFTBUS_ERR;
}

static void UpdateGattService(SoftBusGattService *service, int status)
{
    if (service == NULL) {
        return;
    }
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
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
                if (BleStartLocalListening(NULL) != SOFTBUS_OK) {
                    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleStartLocalListening failed");
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
    (void)pthread_mutex_unlock(&g_connectionLock);
}

static void ResetGattService(SoftBusGattService *service)
{
    if (service == NULL) {
        return;
    }
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
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
    service->svcId = -1;
    service->bleConnCharaId = -1;
    service->bleConnDesId = -1;
    service->bleNetCharaId = -1;
    service->bleNetDesId = -1;
    (void)pthread_mutex_unlock(&g_connectionLock);
}

static void BleServiceAddCallback(int status, SoftBusBtUuid *uuid, int srvcHandle)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ServiceAddCallback srvcHandle=%d\n", srvcHandle);
    if ((uuid == NULL) || (uuid->uuid == NULL)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleServiceAddCallback appUuid is null");
        return;
    }

    if (memcmp(uuid->uuid, SOFTBUS_SERVICE_UUID, uuid->uuidLen) == 0) {
        if (status != SOFTBUS_OK) {
            ResetGattService(&g_gattService);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleRegisterServerCallback failed, status=%d", status);
            return;
        }
        if (pthread_mutex_lock(&g_connectionLock) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
            return;
        }
        if (g_gattService.state != BLE_GATT_SERVICE_ADDING) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "g_gattService wrong state, should be BLE_GATT_SERVICE_ADDING");
            (void)pthread_mutex_unlock(&g_connectionLock);
            return;
        }
        g_gattService.svcId = srvcHandle;
        (void)pthread_mutex_unlock(&g_connectionLock);
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
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleServiceAddCallback unknown uuid");
    }
}

static void BleCharacteristicAddCallback(int status, SoftBusBtUuid *uuid, int srvcHandle,
    int characteristicHandle)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "CharacteristicAddCallback srvcHandle=%d,charHandle=%d\n", srvcHandle,
        characteristicHandle);
    if ((uuid == NULL) || (uuid->uuid == NULL)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleServiceAddCallback appUuid is null");
        return;
    }

    if ((srvcHandle == g_gattService.svcId) && (memcmp(uuid->uuid, SOFTBUS_CHARA_BLENET_UUID, uuid->uuidLen) == 0)) {
        if (status != SOFTBUS_OK) {
            ResetGattService(&g_gattService);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleRegisterServerCallback failed, status=%d", status);
            return;
        }
        if (pthread_mutex_lock(&g_connectionLock) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
            return;
        }
        if (g_gattService.state != BLE_GATT_SERVICE_ADDING) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "g_gattService wrong state, should be BLE_GATT_SERVICE_ADDING");
            (void)pthread_mutex_unlock(&g_connectionLock);
            return;
        }
        g_gattService.bleNetCharaId = characteristicHandle;
        (void)pthread_mutex_unlock(&g_connectionLock);
        return;
    }

    if ((srvcHandle == g_gattService.svcId) && (memcmp(uuid->uuid, SOFTBUS_CHARA_BLECONN_UUID, uuid->uuidLen) == 0)) {
        if (status != SOFTBUS_OK) {
            ResetGattService(&g_gattService);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleRegisterServerCallback failed, status=%d", status);
            return;
        }
        if (pthread_mutex_lock(&g_connectionLock) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
            return;
        }
        if (g_gattService.state != BLE_GATT_SERVICE_ADDING) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "g_gattService wrong state, should be BLE_GATT_SERVICE_ADDING");
            (void)pthread_mutex_unlock(&g_connectionLock);
            return;
        }
        g_gattService.bleConnCharaId = characteristicHandle;
        (void)pthread_mutex_unlock(&g_connectionLock);
        SoftBusMessage *msg = BleConnCreateLoopMsg(ADD_DESCRIPTOR_MSG, 0,
            SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE, SOFTBUS_DESCRIPTOR_CONFIGURE_UUID);
        if (msg == NULL) {
            return;
        }
        g_bleAsyncHandler.looper->PostMessage(g_bleAsyncHandler.looper, msg);
    }
}

static void BleDescriptorAddCallback(int status, SoftBusBtUuid *uuid,
    int srvcHandle, int descriptorHandle)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "DescriptorAddCallback srvcHandle=%d,descriptorHandle=%d\n",
        srvcHandle, descriptorHandle);
    if ((uuid == NULL) || (uuid->uuid == NULL)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleServiceAddCallback appUuid is null");
        return;
    }

    if ((srvcHandle == g_gattService.svcId) &&
        (memcmp(uuid->uuid, SOFTBUS_DESCRIPTOR_CONFIGURE_UUID, uuid->uuidLen) == 0)) {
        if (status != SOFTBUS_OK) {
            ResetGattService(&g_gattService);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleRegisterServerCallback failed, status=%d", status);
            return;
        }
        if (pthread_mutex_lock(&g_connectionLock) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
            return;
        }
        if (g_gattService.state != BLE_GATT_SERVICE_ADDING) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "g_gattService wrong state, should be BLE_GATT_SERVICE_ADDING");
            (void)pthread_mutex_unlock(&g_connectionLock);
            return;
        }
        if (g_gattService.bleNetDesId == -1) {
            g_gattService.bleNetDesId = descriptorHandle;
        } else {
            g_gattService.bleConnDesId = descriptorHandle;
            UpdateGattService(&g_gattService, 0);
        }
        (void)pthread_mutex_unlock(&g_connectionLock);
    } else {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleDescriptorAddCallback unknown srvcHandle or uuid");
    }
}

static void BleServiceStartCallback(int status, int srvcHandle)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ServiceStartCallback srvcHandle=%d\n", srvcHandle);
    if (srvcHandle != g_gattService.svcId) {
        return;
    }
    if (status != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleServiceStartCallback start failed");
    }
    UpdateGattService(&g_gattService, status);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleServiceStartCallback start success");
}

static void BleServiceStopCallback(int status, int srvcHandle)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ServiceStopCallback srvcHandle=%d\n", srvcHandle);
    if (srvcHandle != g_gattService.svcId) {
        return;
    }
    if (status != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleServiceStopCallback stop failed");
    }
    UpdateGattService(&g_gattService, status);
}

static void BleServiceDeleteCallback(int status, int srvcHandle)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ServiceDeleteCallback srvcHandle=%d\n", srvcHandle);
    if (srvcHandle != g_gattService.svcId) {
        return;
    }
    if (status != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleServiceStopCallback stop failed");
    }
    UpdateGattService(&g_gattService, status);
}

static void BleConnectServerCallback(int connId, const SoftBusBtAddr *btAddr)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConnectServerCallback is coming, halConnId=%d\n", connId);
    char bleMac[BT_MAC_LEN];
    int ret = ConvertBtMacToStr(bleMac, BT_MAC_LEN, btAddr->addr, BT_ADDR_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Convert ble addr failed:%d", ret);
        return;
    }
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_conection_list) {
        BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->halConnId == connId) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleConnectServerCallback exist same connId, exit");
            (void)pthread_mutex_unlock(&g_connectionLock);
            return;
        }
    }
    BleConnectionInfo *newNode = CreateBleConnectionNode();
    newNode->halConnId = connId;
    if (memcpy_s(newNode->btBinaryAddr.addr, BT_ADDR_LEN, btAddr->addr, BT_ADDR_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleConnectServerCallback memcpy_s error");
        SoftBusFree(newNode);
        (void)pthread_mutex_unlock(&g_connectionLock);
        return;
    }
    if (memcpy_s(newNode->info.info.bleInfo.bleMac, BT_MAC_LEN, bleMac, BT_MAC_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleConnectServerCallback memcpy_s error");
        SoftBusFree(newNode);
        (void)pthread_mutex_unlock(&g_connectionLock);
        return;
    }
    newNode->info.isServer = 1;
    newNode->state = BLE_CONNECTION_STATE_CONNECTED;
    ListTailInsert(&g_conection_list, &(newNode->node));
    (void)pthread_mutex_unlock(&g_connectionLock);
    g_connectCallback->OnConnected(newNode->connId, &(newNode->info));
}

static void BleDisconnectServerCallback(int connId, const SoftBusBtAddr *btAddr)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "DisconnectServerCallback is coming, halconnId=%d", connId);
    char bleMac[BT_MAC_LEN];
    int ret = ConvertBtMacToStr(bleMac, BT_MAC_LEN, btAddr->addr, BT_ADDR_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Convert ble addr failed:%d", ret);
        return;
    }
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    BleConnectionInfo *targetNode = NULL;
    LIST_FOR_EACH_SAFE(item, nextItem, &g_conection_list) {
        BleConnectionInfo *itemNode = LIST_ENTRY(item, BleConnectionInfo, node);
        if (itemNode->halConnId == connId) {
            targetNode = itemNode;
            itemNode->state = BLE_CONNECTION_STATE_CLOSED;
            ListDelete(&(itemNode->node));
            DeleteBleConnectionNode(itemNode);
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    if (targetNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleDisconnectServerCallback unknown halconnId:%d", connId);
        return;
    }
    g_connectCallback->OnDisconnected(targetNode->connId, &(targetNode->info));
}

int SendSelfBasicInfo(uint32_t connId)
{
    cJSON *json =  cJSON_CreateObject();
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot create cJSON object");
        return SOFTBUS_ERR;
    }
    char devId[UUID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, devId, UDID_BUF_LEN) != SOFTBUS_OK) {
        cJSON_Delete(json);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendSelfBasicInfo Get local dev Id failed.");
        return SOFTBUS_ERR;
    }
    if (!AddStringToJsonObject(json, "devid", devId)) {
        cJSON_Delete(json);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendSelfBasicInfo Cannot add devid to jsonobj");
        return SOFTBUS_ERR;
    }
    if (!AddNumberToJsonObject(json, "type", BLE_ROLE_SERVER)) {
        cJSON_Delete(json);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendSelfBasicInfo Cannot add type to jsonobj");
        return SOFTBUS_ERR;
    }

    char *data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "cJSON_PrintUnformatted failed");
        return SOFTBUS_ERR;
    }
    int32_t dataLen = strlen(data) + 1 + TYPE_HEADER_SIZE;
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
    int ret = BlePostBytesInner(connId, &postData);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendSelfBasicInfo BlePostBytesInner failed");
        SoftBusFree(buf);
    }
    return ret;
}

int PeerBasicInfoParse(BleConnectionInfo *connInfo, const char *value, int32_t len)
{
    cJSON *data = NULL;
    data = cJSON_Parse(value + TYPE_HEADER_SIZE);
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

static void BleOnDataReceived(int32_t handle, int32_t halConnId, uint32_t len, const char *value)
{
    if (value == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleOnDataReceived invalid data");
        return;
    }
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    BleConnectionInfo *targetNode = GetBleConnInfoByHalConnId(halConnId);
    if (targetNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleOnDataReceived unknown device");
        (void)pthread_mutex_unlock(&g_connectionLock);
        return;
    }
    if (handle == g_gattService.bleConnCharaId) {
        ConnPktHead *head = (ConnPktHead *)value;
        if (head->module == MODULE_CONNECTION) {
            cJSON *data = NULL;
            data = cJSON_Parse(value + sizeof(ConnPktHead));
            if (data == NULL) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[receive data invalid]");
                (void)pthread_mutex_unlock(&g_connectionLock);
                return;
            }
            RecvConnectedComd(targetNode->connId, (const cJSON*)data);
            cJSON_Delete(data);
        } else {
            if (head->len + sizeof(ConnPktHead) > len) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BLEINFOPRTINT: recv a big data:%d, not support",
                    head->len + sizeof(ConnPktHead));
            }
            if (g_connectCallback != NULL) {
                g_connectCallback->OnDataReceived(targetNode->connId, (ConnModule)head->module, head->seq,
                    (char *)value, head->len + sizeof(ConnPktHead));
            }
        }
    } else {
        if (targetNode->state == BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED) {
            g_connectCallback->OnDataReceived(targetNode->connId, MODULE_BLE_NET, 0, (char *)value, len);
        } else {
            if (PeerBasicInfoParse(targetNode, value, len) != SOFTBUS_OK) {
                (void)pthread_mutex_unlock(&g_connectionLock);
                return;
            }
            targetNode->state = BLE_CONNECTION_STATE_BASIC_INFO_EXCHANGED;
            SendSelfBasicInfo(targetNode->connId);
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
}

static void BleRequestReadCallback(SoftBusGattReadRequest readCbPara)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RequestReadCallback transId=%d, attrHandle=%d\n",
        readCbPara.transId, readCbPara.attrHandle);
    SoftBusGattsResponse response = {
        .connectId = readCbPara.connId,
        .status = SOFTBUS_BT_STATUS_SUCCESS,
        .attrHandle = readCbPara.transId,
        .valueLen = 13,
        .value = "not support!"
    };
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleRequestReadCallback sendresponse");
    SoftBusGattsSendResponse(&response);
}

static void BleRequestWriteCallback(SoftBusGattWriteRequest writeCbPara)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RequestWriteCallback halconnId=%d, transId=%d, attrHandle=%d\n",
        writeCbPara.connId, writeCbPara.transId, writeCbPara.attrHandle);
    if (writeCbPara.attrHandle != g_gattService.bleConnCharaId &&
        writeCbPara.attrHandle != g_gattService.bleNetCharaId) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleOnDataReceived not support handle :%d expect:%d",
            writeCbPara.attrHandle, g_gattService.bleConnCharaId);
        return;
    }
    if (writeCbPara.needRsp) {
        SoftBusGattsResponse response = {
            .connectId = writeCbPara.connId,
            .status = SOFTBUS_BT_STATUS_SUCCESS,
            .attrHandle = writeCbPara.transId,
            .valueLen = writeCbPara.length,
            .value = (char *)writeCbPara.value
        };
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleRequestWriteCallback sendresponse");
        SoftBusGattsSendResponse(&response);
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
        "BLEINFOPRTINT:BleRequestWriteCallback valuelen:%d value:)", writeCbPara.length);
    uint32_t len;
    int32_t index = -1;
    char *value = BleTransRecv(writeCbPara.connId, (char *)writeCbPara.value,
        (uint32_t)writeCbPara.length, &len, &index);
    if (value == NULL) {
        return;
    }
    BleOnDataReceived(writeCbPara.attrHandle, writeCbPara.connId, len, (const char *)value);
    if (index != -1) {
        BleTransCacheFree(writeCbPara.connId, index);
    }
}

static void BleResponseConfirmationCallback(int status, int handle)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "ResponseConfirmationCallback status=%d, handle=%d\n", status, handle);
}

static void BleNotifySentCallback(int connId, int status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "IndicationSentCallback status=%d, connId=%d\n", status, connId);
}

static void BleMtuChangeCallback(int connId, int mtu)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "MtuChangeCallback connId=%d, mtu=%d\n", connId, mtu);
    BleConnectionInfo *connInfo = GetBleConnInfoByConnId(connId);
    if (connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleMtuChangeCallback GetBleConnInfo failed");
        return;
    }
    connInfo->mtu = mtu;
}

static int32_t SendBleData(SendQueueNode *node)
{
    if (node->len > MAX_DATA_LEN) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendBleData big msg, len:%d\n", node->len);
    }
    if (node->isServer == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendBleData ble gatt client not support");
        return SOFTBUS_ERR;
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
    while (1) {
        SendQueueNode *node = NULL;
        if (BleDequeueBlock((void **)(&node)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get sendItem failed");
            continue;
        }
        if (SendBleData(node) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendItem fail");
        }
        FreeSendNode(node);
    }
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

static void InitBleInterface(void)
{
    g_bleInterface.ConnectDevice = BleConnectDevice;
    g_bleInterface.PostBytes = BlePostBytes;
    g_bleInterface.DisconnectDevice = BleDisconnectDevice;
    g_bleInterface.DisconnectDeviceNow = BleDisconnectDeviceNow;
    g_bleInterface.GetConnectionInfo = BleGetConnectionInfo;
    g_bleInterface.StartLocalListening = BleStartLocalListening;
    g_bleInterface.StopLocalListening = BleStopLocalListening;
}

static void BleConnMsgHandler(SoftBusMessage *msg)
{
    SoftBusBtUuid uuid;
    int properties, permissions;
    if (msg == NULL) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ble conn loop process msg type %d", msg->what);
    switch (msg->what) {
        case ADD_SERVICE_MSG:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "call GattsRegisterCallback");
            int ret = GattsRegisterCallback();
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GattsRegisterCallbacks failed：%d", ret);
                return;
            }
            if (pthread_mutex_lock(&g_connectionLock) != 0) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
                return;
            }
            g_gattService.state = BLE_GATT_SERVICE_ADDING;
            (void)pthread_mutex_unlock(&g_connectionLock);
            uuid.uuid = (char *)msg->obj;
            uuid.uuidLen = BT_UUID_LEN;
            ret = SoftBusGattsAddService(uuid, true, MAX_SERVICE_CHAR_NUM);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGattsAddService failed:%d", ret);
                return;
            }
            break;
        case ADD_CHARA_MSG:
            uuid.uuid = (char *)msg->obj;
            uuid.uuidLen = BT_UUID_LEN;
            properties = (int)msg->arg1;
            permissions = (int)msg->arg2;
            ret = SoftBusGattsAddCharacteristic(g_gattService.svcId, uuid, properties, permissions);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGattsAddCharacteristic  failed:%d", ret);
                return;
            }
            break;
        case ADD_DESCRIPTOR_MSG:
            uuid.uuid = (char *)msg->obj;
            uuid.uuidLen = BT_UUID_LEN;
            permissions = (int)msg->arg2;
            ret = SoftBusGattsAddDescriptor(g_gattService.svcId, uuid, permissions);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGattsAddDescriptor  failed:%d", ret);
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

static int BleQueueInit(void)
{
    uint32_t sendQueueSize;
    int ret = QueueSizeCalc(SEND_QUEUE_UNIT_NUM, &sendQueueSize);
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    g_sendQueue.queue = (LockFreeQueue *)SoftBusCalloc(sendQueueSize);
    if (g_sendQueue.queue == NULL) {
        return SOFTBUS_ERR;
    }
    ret = QueueInit(g_sendQueue.queue, SEND_QUEUE_UNIT_NUM);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(g_sendQueue.queue);
        g_sendQueue.queue = NULL;
        return SOFTBUS_ERR;
    }
    pthread_mutex_init(&g_sendQueue.lock, NULL);
    pthread_cond_init(&g_sendQueue.cond, NULL);
    pthread_t tid;
    if (pthread_create(&tid, NULL, BleSendTask, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create BleSendTask failed");
        SoftBusFree(g_sendQueue.queue);
        g_sendQueue.queue = NULL;
        pthread_cond_destroy(&g_sendQueue.cond);
        pthread_mutex_destroy(&g_sendQueue.lock);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void BleConnOnBtStateChanged(int listenerId, int state)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[BleOnBtStateChanged] id:%d, state:%d", listenerId, state);
    if (state == SOFTBUS_BT_STATE_TURN_ON) {
        SoftBusMessage *msg = BleConnCreateLoopMsg(ADD_SERVICE_MSG, 0, 0, SOFTBUS_SERVICE_UUID);
        if (msg == NULL) {
            return;
        }
        g_bleAsyncHandler.looper->PostMessage(g_bleAsyncHandler.looper, msg);
    }
}

static SoftBusBtStateListener g_bleConnStateListener = {
    .OnBtStateChanged = BleConnOnBtStateChanged
};

ConnectFuncInterface *ConnInitBle(const ConnectCallback *callback)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[InitBle]");
    int ret;
    ret = BleConnLooperInit();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleConnLoopInit failed：%d", ret);
        return NULL;
    }
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_connectionLock, &attr);
    ret = BleQueueInit();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleQueueInit failed：%d", ret);
        return NULL;
    }
    ret = SoftBusAddBtStateListener(&g_bleConnStateListener);
    if (ret < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusAddBtStateListener failed：%d", ret);
        return NULL;
    }
    ret = SoftBusEnableBt();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusAddBtStateListener failed：%d", ret);
        return NULL;
    }
    g_connectCallback = (ConnectCallback*)callback;
    InitBleInterface();
    return &g_bleInterface;
}