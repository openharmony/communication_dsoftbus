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

#include <sys/prctl.h>

#include "cJSON.h"
#include "cmsis_os2.h"
#include "common_list.h"
#include "message_handler.h"
#include "ohos_types.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_type_def.h"
#include "stdbool.h"
#include "string.h"
#include "time.h"
#include "unistd.h"
#include "wrapper_br_interface.h"

#define KEY_METHOD "KEY_METHOD"
#define KEY_DELTA "KEY_DELTA"
#define KEY_REFERENCE_NUM "KEY_REFERENCE_NUM"
#define METHOD_NOTIFY_REQUEST 1
#define METHOD_NOTIFY_RESPONSE 2
#define METHOD_SHUT_DOWN 3
#define DISCONN_DELAY_TIME 200
#define MAGIC_NUMBER  0xBABEFACE
#define TIMEOUT_DISCONNECT 1000
#define CONNECT_REF_INCRESE 1
#define CONNECT_REF_DECRESE (-1)
#define BR_CONNECT_TEST 1588
#define BR_CLIENT_TYPE 0
#define BR_MAC_PRINT 17
#define BR_SERVICE_TYPE 1
#define BT_RFCOM_CONGEST_ON 0
#define BT_RFCOM_CONGEST_OFF 1
#define BR_NOTIFY_REQUESTID 1
#define BR_NOTIFY_REQUESTID_DISCONNECT 2
#define BR_STATE_RECAVER 5
#define BR_CONNECT_TASK 10
#define BR_SEND_THREAD_STACK 3072
#define BR_RECE_THREAD_STACK 4096
#define MAX_BR_SIZE (32*1024)
#define MAX_BR_PEER_SIZE (3*1024)
#define INVALID_LENGTH (-1)
#define PRIORITY_HIGH 64
#define PRIORITY_MID 8
#define PRIORITY_LOW 1
#define PRIORITY_DAF 1
#define INVALID_VALUE (-1)
#define MAX_BR_SENDQUEQUE_SIZE (10*10)
#define BT_ADDR_LEN_RFCOM 6

typedef struct {
    ListNode node;
    int32_t requestId;
    ConnectResult callback;
} RequestInfo;

typedef struct {
    ListNode node;
    uint32_t connectionId;
    int32_t socketFd;
    int32_t sideType;
    char mac[BT_MAC_LEN];
    int32_t connectQueueState;
    int32_t state;
    int32_t refCount;
    int32_t refCountRemote;
    char *recvBuf;
    int32_t recvPos;
    int32_t conGestState;
    ListNode requestList;
    pthread_mutex_t lock;
    pthread_cond_t congestCond;
} BrConnectionInfo;

typedef struct {
    ListNode node;
    uint32_t connectionId;
    int32_t pid;
    int32_t priority;
    uint32_t dataLen;
    int32_t sendPos;
    char *data;
} SendItemStruct;

typedef struct {
    ListNode node;
    int32_t pid;
    int32_t itemCount;
} DataPidQueueStruct;

typedef struct {
    ListNode sendList;
    ListNode pidList;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    SoftBusHandler *handler;
} DataQueueStruct;

typedef struct {
    ListNode node;
    uint32_t connectionId;
    int32_t module;
    long seqNum;
    int32_t flag;
    uint32_t dataLen;
    uint8_t *data;
} ReceiveItemStruct;

typedef struct {
    ListNode recvList;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    SoftBusHandler *handler;
} RecvQueueStruct;

enum BRConnectionState {
    BR_CONNECTION_STATE_CONNECTING = 0,
    BR_CONNECTION_STATE_CONNECTED,
    BR_CONNECTION_STATE_CLOSING,
    BR_CONNECTION_STATE_CLOSED
};

static void ClientOnEvent(int32_t type, int32_t socketFd, int32_t value);

static void ClientOnDataReceived(int32_t socketFd, const char *buf, int32_t len);

static void ServerOnEvent(int32_t type, int32_t socketFd, int32_t value);

static void ServerOnDataReceived(int32_t socketFd, const char *buf, int32_t len);

static bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int *target);

static bool AddNumberToJsonObject(cJSON *obj, const char * const string, int32_t num);

static int32_t ConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result);

static int32_t PostBytes(uint32_t connectionId, const char *data, int32_t len, int32_t pid, int32_t flag);

static int32_t DisconnectDevice(uint32_t connectionId);

static int32_t DisconnectDeviceNow(const ConnectOption *option);

static int32_t GetConnectionInfo(uint32_t connectionId, ConnectionInfo *info);

static int32_t StartLocalListening(const LocalListenerInfo *info);

static int32_t StopLocalListening(const LocalListenerInfo *info);

static void ClientOnBrDisconnect(int32_t socketFd, int32_t value);

static void ClearSendItemByConnId(uint32_t connectionId);

static void ClearReceiveQueueByConnId(uint32_t connectionId);

static int32_t ConvertBtMacToBinary(char *strMac, int32_t strMacLen,
    const uint8_t *binMac, int32_t binMacLen)
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

static SppSocketEventCallback g_sppSocketClientCallback = {
    .OnEvent = ClientOnEvent,
    .OnDataReceived = ClientOnDataReceived
};


static SppSocketEventCallback g_sppSocketServiceCallback = {
    .OnEvent = ServerOnEvent,
    .OnDataReceived = ServerOnDataReceived
};

static ConnectFuncInterface g_brInterface = {
    .ConnectDevice = ConnectDevice,
    .PostBytes = PostBytes,
    .DisconnectDevice = DisconnectDevice,
    .DisconnectDeviceNow = DisconnectDeviceNow,
    .GetConnectionInfo = GetConnectionInfo,
    .StartLocalListening = StartLocalListening,
    .StopLocalListening = StopLocalListening
};

static pthread_mutex_t g_connectionLock;
static const uint8_t UUID[BT_UUID_LEN] = {
    0x8c, 0xe2, 0x55, 0xc0, 0x20, 0x0a, 0x11, 0xe0,
    0xac, 0x64, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66
};

static LIST_HEAD(g_conection_list);
static DataQueueStruct g_dataQueue;
static RecvQueueStruct g_recvQueue;
static SppSocketDriver *g_sppDriver = NULL;
static ConnectCallback *g_connectCallback = NULL;

static int16_t g_nextConnectionId = 0;
static int32_t g_brBuffSize;
static int32_t g_brSendPeerLen;
static int32_t g_brSendQueueMaxLen;
static int32_t AllocNewConnectionIdLocked()
{
    g_nextConnectionId++;
    int32_t tempId;
    while (1) {
        tempId = (CONNECT_BR << CONNECT_TYPE_SHIFT) + g_nextConnectionId;
        ListNode *item = NULL;
        LIST_FOR_EACH(item, &g_conection_list) {
            BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
            if (itemNode->connectionId == tempId) {
                g_nextConnectionId++;
                continue;
            }
        }
        break;
    }
    return tempId;
}

static int32_t GetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    int32_t result = SOFTBUS_ERR;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_conection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->connectionId == connectionId) {
            info->isAvailable = 1;
            info->isServer = itemNode->sideType;
            info->type = CONNECT_BR;
            if (strncpy_s(info->info.brInfo.brMac, BT_MAC_LEN,
                itemNode->mac, sizeof(itemNode->mac)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetConnInfo scpy error");
                (void)pthread_mutex_unlock(&g_connectionLock);
                return SOFTBUS_BRCONNECTION_GETCONNINFO_ERROR;
            }
            result = SOFTBUS_OK;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return result;
}

static BrConnectionInfo *GetConnectionRef(uint32_t connID)
{
    BrConnectionInfo *result = NULL;
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_conection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->connectionId == connID) {
            result = itemNode;
            break;
        }
    }
    return result;
}

static void ReleaseConnection(BrConnectionInfo *conn)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ReleaseConnection node + %u", conn->connectionId);
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    LIST_FOR_EACH_SAFE(item, nextItem, &conn->requestList) {
        RequestInfo *requestInfo = LIST_ENTRY(item, RequestInfo, node);
        ListDelete(&(requestInfo->node));
        SoftBusFree(requestInfo);
    }
    pthread_cond_destroy(&conn->congestCond);
    pthread_mutex_destroy(&conn->lock);
    SoftBusFree(conn->recvBuf);
    SoftBusFree(conn);
}

static void ReleaseConnectionRef(BrConnectionInfo *conn)
{
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    ListDelete(&conn->node);
    ReleaseConnection(conn);
    (void)pthread_mutex_unlock(&g_connectionLock);
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
    head.magic = MAGIC_NUMBER;
    head.module = MODULE_CONNECTION;
    head.seq = 1;
    head.flag = 0;
    head.len = strlen(data) + 1;

    if (memcpy_s(buf, dataLen, (void *)&head, headSize)) {
        cJSON_free(data);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s head error");
        cJSON_free(data);
        SoftBusFree(buf);
        return;
    }
    if (memcpy_s(buf + headSize, dataLen - headSize, data, strlen(data) + 1)) {
        cJSON_free(data);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s data error");
        cJSON_free(data);
        SoftBusFree(buf);
        return;
    }
    (void)PostBytes(connectionId, buf, dataLen, 0, 0);
    cJSON_free(data);
    return;
}

static void PackRequest(int32_t delta, int32_t connectionId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[onNotifyRequest: delta=%d, connectionIds=%u", delta, connectionId);
    ListNode *item = NULL;
    BrConnectionInfo *targetNode = NULL;
    int refCount;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    LIST_FOR_EACH(item, &g_conection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->connectionId == connectionId) {
            itemNode->refCount += delta;
            refCount = itemNode->refCount;
            targetNode = itemNode;
            break;
        }
    }
    if (targetNode == NULL) {
        (void)pthread_mutex_unlock(&g_connectionLock);
        return;
    }
    (void)pthread_mutex_unlock(&g_connectionLock);

    SendRefMessage(delta, connectionId, refCount, METHOD_NOTIFY_REQUEST);
}

static void OnPackResponse(int32_t delta, int32_t peerRef, int32_t connectionId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "[onNotifyRequest: delta=%d, RemoteRef=%d, connectionIds=%u", delta, peerRef, connectionId);
    ListNode *item = NULL;
    BrConnectionInfo *targetNode = NULL;
    int myRefCount;
    int mySocketFd;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    LIST_FOR_EACH(item, &g_conection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->connectionId == connectionId) {
            targetNode = itemNode;
            targetNode->refCount += delta;
            myRefCount = targetNode->refCount;
            mySocketFd = targetNode->socketFd;
            break;
        }
    }
    if (targetNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "Not find OnPackResponse device");
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
        g_sppDriver->CloseClient(mySocketFd);
        return;
    }
    SendRefMessage(delta, connectionId, myRefCount, METHOD_NOTIFY_RESPONSE);
}

static int32_t HasDiffMacDeviceExit(const ConnectOption *option)
{
    if (IsListEmpty(&g_conection_list)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[g_conection_list is empty, allow to connect device.]");
        return 0;
    }
    ListNode *item = NULL;
    int32_t res;
    LIST_FOR_EACH(item, &g_conection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (memcmp(itemNode->mac, option->info.brOption.brMac, sizeof(itemNode->mac)) == 0 &&
            itemNode->sideType == BR_CLIENT_TYPE) {
            res = SOFTBUS_OK;
        } else {
            res = SOFTBUS_ERR;
            break;
        }
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[check HasDiffMacDeviceExit, return value is %d", res);
    return res;
}

static void ReleaseBrconnectionNode(BrConnectionInfo *newConnectionInfo)
{
    if (newConnectionInfo == NULL) {
        return;
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ReleaseBrconnectionNode");
    pthread_cond_destroy(&newConnectionInfo->congestCond);
    pthread_mutex_destroy(&newConnectionInfo->lock);
    if (newConnectionInfo->recvBuf != NULL) {
        SoftBusFree(newConnectionInfo->recvBuf);
    }
    RequestInfo *requestInfo = NULL;
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    if (IsListEmpty(&newConnectionInfo->requestList) != true) {
        LIST_FOR_EACH_SAFE(item, itemNext, &newConnectionInfo->requestList) {
            requestInfo = LIST_ENTRY(item, RequestInfo, node);
            ListDelete(&requestInfo->node);
            SoftBusFree(requestInfo);
        }
    }
    SoftBusFree(newConnectionInfo);
    return;
}

static BrConnectionInfo* CreateBrconnectionNode(int clientFlag)
{
    BrConnectionInfo *newConnectionInfo = SoftBusCalloc(sizeof(BrConnectionInfo));
    if (newConnectionInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ConnectDeviceFristTime malloc fail.]");
        return NULL;
    }
    newConnectionInfo->recvBuf = SoftBusCalloc(g_brBuffSize);
    if (newConnectionInfo->recvBuf == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[SoftBusMalloc recvBuf fail]");
        SoftBusFree(newConnectionInfo);
        return NULL;
    }
    ListInit(&newConnectionInfo->node);
    ListInit(&newConnectionInfo->requestList);
    pthread_mutex_init(&newConnectionInfo->lock, NULL);
    newConnectionInfo->connectionId = AllocNewConnectionIdLocked();
    newConnectionInfo->recvPos = 0;
    newConnectionInfo->conGestState = BT_RFCOM_CONGEST_OFF;
    pthread_cond_init(&newConnectionInfo->congestCond, NULL);
    newConnectionInfo->refCount = 1;
    return newConnectionInfo;
}

static int32_t ConnectDeviceFristTime(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    BrConnectionInfo *newConnectionInfo = CreateBrconnectionNode(true);
    if (newConnectionInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[client node create fail]");
        return SOFTBUS_ERR;
    }
    RequestInfo *requestInfo = SoftBusCalloc(sizeof(RequestInfo));
    if (requestInfo == NULL) {
        ReleaseBrconnectionNode(newConnectionInfo);
        return NULL;
    }
    ListInit(&requestInfo->node);
    ListAdd(&newConnectionInfo->requestList, &requestInfo->node);
    strncpy_s(newConnectionInfo->mac, sizeof(newConnectionInfo->mac),
        option->info.brOption.brMac, BT_MAC_LEN);
    // init lock

    requestInfo->requestId = requestId;
    (void)memcpy_s(&requestInfo->callback, sizeof(requestInfo->callback), result, sizeof(*result));
    newConnectionInfo->state = BR_CONNECTION_STATE_CONNECTING;
    newConnectionInfo->sideType = BR_CLIENT_TYPE;
    int32_t socketFd = SOFTBUS_ERR;
    uint8_t btAddr[BT_ADDR_LEN];

    if (ConvertBtMacToBinary(newConnectionInfo->mac, BT_MAC_LEN, btAddr, BT_ADDR_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "convert bt mac to binary fail.]");
        ReleaseBrconnectionNode(newConnectionInfo);
        return SOFTBUS_ERR;
    }
    if (g_sppDriver != NULL) {
        socketFd = g_sppDriver->OpenSppClient(btAddr, UUID, 0);
    }
    if (socketFd == SOFTBUS_ERR) {
        ReleaseBrconnectionNode(newConnectionInfo);
        return SOFTBUS_BRCONNECTION_CONNECTDEVICE_GETSOCKETIDFAIL;
    }
    newConnectionInfo->socketFd = socketFd;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "[new connection %d,socket=%d", newConnectionInfo->connectionId, socketFd);
    ListAdd(&g_conection_list, &newConnectionInfo->node);
    int32_t ret = g_sppDriver->Connect(socketFd, &g_sppSocketClientCallback);
    return ret;
}

static void ConnectDeviceExit(const BrConnectionInfo *itemNode, uint32_t requestId, const ConnectResult *result)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[already find mac in g_conection_list]");
    ConnectionInfo connectionInfo;
    connectionInfo.isAvailable = 1;
    connectionInfo.isServer = itemNode->sideType;
    connectionInfo.type = CONNECT_BR;
    strncpy_s(connectionInfo.info.brInfo.brMac, BT_MAC_LEN,
        itemNode->mac, sizeof(itemNode->mac));
    int connectionId = itemNode->connectionId;

    (void)pthread_mutex_unlock(&g_connectionLock);
    if (result->OnConnectSuccessed != NULL) {
        result->OnConnectSuccessed(
            requestId, connectionId, &connectionInfo);
    }

    (void)PackRequest(CONNECT_REF_INCRESE, connectionId);
}

int32_t ConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    int32_t ret = SOFTBUS_OK;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ConnectDevice]");
    if (HasDiffMacDeviceExit(option) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
            "[g_conection_list has diff mac device, mini system not support.]");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    ListNode *item = NULL;
    BrConnectionInfo *targetConnectionInfo = NULL;
    LIST_FOR_EACH(item, &g_conection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (strncmp(itemNode->mac, option->info.brOption.brMac, BT_MAC_LEN) == 0) {
            targetConnectionInfo = itemNode;
            if (itemNode->state == BR_CONNECTION_STATE_CONNECTED) {
                ConnectDeviceExit(itemNode, requestId, result);
                return SOFTBUS_OK;
            } else if (itemNode->state == BR_CONNECTION_STATE_CONNECTING) {
                RequestInfo *requestInfo = SoftBusMalloc(sizeof(RequestInfo));
                if (requestInfo == NULL) {
                    (void)pthread_mutex_unlock(&g_connectionLock);
                    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
                        "[ConnectDevice fail and state is BR_CONNECTION_STATE_CONNECTING.]");
                    return SOFTBUS_ERR;
                }
                (void)memset_s(requestInfo, sizeof(RequestInfo), 0, sizeof(RequestInfo));
                ListInit(&requestInfo->node);
                requestInfo->requestId = requestId;
                (void)memcpy_s(&requestInfo->callback, sizeof(requestInfo->callback), result, sizeof(*result));
                ListAdd(&itemNode->requestList, &requestInfo->node);
                ret = SOFTBUS_OK;
            } else if (itemNode->state == BR_CONNECTION_STATE_CLOSING) {
                result->OnConnectFailed(requestId, 0);
                ret = SOFTBUS_OK;
            }
        }
    }
    if (targetConnectionInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[targetConnectionInfo == NULL]");
        ret = ConnectDeviceFristTime(option, requestId, result);
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return ret;
}

static void DeviceConnectPackRequest(int32_t value, int32_t connectionId)
{
    while (--value > 0) {
        (void)PackRequest(CONNECT_REF_INCRESE, connectionId);
    }
}

void RfcomCongestEvent(int32_t socketFd, int32_t value)
{
    ListNode *item = NULL;
    BrConnectionInfo *itemNode = NULL;

    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    LIST_FOR_EACH(item, &g_conection_list) {
        itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->socketFd == socketFd) {
            itemNode->conGestState = value;
            if (value == BT_RFCOM_CONGEST_OFF) {
                if (pthread_mutex_lock(&itemNode->lock) != 0) {
                    (void)pthread_mutex_unlock(&g_connectionLock);
                    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock itemNode failed");
                    return;
                }
                pthread_cond_broadcast(&itemNode->congestCond);
                (void)pthread_mutex_unlock(&itemNode->lock);
            }
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
}

static void ClientOnBrConnect(int32_t socketFd)
{
    ListNode notifyList;
    ListInit(&notifyList);
    ListNode *britem = NULL;
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    RequestInfo *requestInfo = NULL;
    ConnectionInfo connectionInfo;
    (void)pthread_mutex_lock(&g_connectionLock);
    int32_t connectionId = 0;
    int32_t packRequestFlag = 0;
    LIST_FOR_EACH(britem, &g_conection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(britem, BrConnectionInfo, node);
        if (itemNode->socketFd == socketFd) {
            connectionInfo.isAvailable = 1;
            connectionInfo.isServer = itemNode->sideType;
            connectionInfo.type = CONNECT_BR;
            strncpy_s(connectionInfo.info.brInfo.brMac, BT_MAC_LEN,
                itemNode->mac, sizeof(itemNode->mac));
            connectionId = itemNode->connectionId;
            itemNode->state = BR_CONNECTION_STATE_CONNECTED;
            LIST_FOR_EACH_SAFE(item, itemNext, &itemNode->requestList) {
                requestInfo = LIST_ENTRY(item, RequestInfo, node);
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ClientOnEvent] requestId=%d, connectionId=%u",
                    requestInfo->requestId, itemNode->connectionId);
                ListDelete(&requestInfo->node);
                ListAdd(&notifyList, &requestInfo->node);
                packRequestFlag++;
            }
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    if (connectionId != 0) {
        DeviceConnectPackRequest(packRequestFlag, connectionId);
        LIST_FOR_EACH_SAFE(item, itemNext, &notifyList) {
            requestInfo = LIST_ENTRY(item, RequestInfo, node);
            if (requestInfo->callback.OnConnectSuccessed != NULL) {
                requestInfo->callback.OnConnectSuccessed(
                    requestInfo->requestId, connectionId, &connectionInfo);
            }
            ListDelete(&requestInfo->node);
            SoftBusFree(requestInfo);
        }
    }
}

static void ClientOnEvent(int32_t type, int32_t socketFd, int32_t value)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ClientOnEvent] type=%d, socketFd=%d", type, socketFd);
    if (type == SPP_EVENT_TYPE_CONNECTED) {
        ClientOnBrConnect(socketFd);
    } else if (type == SPP_EVENT_TYPE_DISCONNECTED) {
        ClientOnBrDisconnect(socketFd, value);
    } else if (type == SPP_EVENT_TYPE_CONGEST) {
        RfcomCongestEvent(socketFd, value);
    }
}

static int32_t InitConnectionInfo(ConnectionInfo *connectionInfo, const BrConnectionInfo *itemNode)
{
    (*connectionInfo).isAvailable = 0;
    (*connectionInfo).isServer = itemNode->sideType;
    (*connectionInfo).type = CONNECT_BR;
    if (strncpy_s((*connectionInfo).info.brInfo.brMac, BT_MAC_LEN,
        itemNode->mac, sizeof(itemNode->mac)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "InitConnInfo scpy error");
            return SOFTBUS_BRCONNECTION_STRNCPY_ERROR;
    }
    return SOFTBUS_OK;
}

static void FreeCongestEvent(BrConnectionInfo *itemNode)
{
    itemNode->conGestState = BT_RFCOM_CONGEST_OFF;
    if (pthread_mutex_lock(&itemNode->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "FreeCongestEvent mutex failed");
        return;
    }
    pthread_cond_broadcast(&itemNode->congestCond);
    (void)pthread_mutex_unlock(&itemNode->lock);
}

static void NotifyDisconnect(const ListNode *notifyList, int32_t connectionId,
    ConnectionInfo connectionInfo, int32_t value)
{
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    if (IsListEmpty(notifyList) != true) {
        LIST_FOR_EACH_SAFE(item, itemNext, notifyList) {
            RequestInfo *requestInfo = LIST_ENTRY(item, RequestInfo, node);
            if (requestInfo->callback.OnConnectFailed != NULL) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ClientOnEvent] disconn connectionId=%d", connectionId);
                requestInfo->callback.OnConnectFailed(requestInfo->requestId, value);
            }
            ListDelete(&requestInfo->node);
            SoftBusFree(requestInfo);
        }
    }

    if (g_connectCallback != NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ClientOnEvent] disconn connectionId=%d", connectionId);
        g_connectCallback->OnDisconnected(connectionId, &connectionInfo);
    }
}

static void ClientOnBrDisconnect(int32_t socketFd, int32_t value)
{
    ListNode *britem = NULL;
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    int32_t connectionId = -1;
    ListNode notifyList;
    ListInit(&notifyList);
    ConnectionInfo connectionInfo;
    BrConnectionInfo *brNode = NULL;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ClientOnBrDisconnect mutex failed");
        return;
    }
    LIST_FOR_EACH(britem, &g_conection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(britem, BrConnectionInfo, node);
        if (itemNode->socketFd == socketFd) {
            brNode = itemNode;
            itemNode->state = BR_CONNECTION_STATE_CLOSED;
            FreeCongestEvent(itemNode);
            if (InitConnectionInfo(&connectionInfo, itemNode) != SOFTBUS_OK) {
                (void)pthread_mutex_unlock(&g_connectionLock);
                return;
            }
            connectionId = itemNode->connectionId;
            LIST_FOR_EACH_SAFE(item, itemNext, &itemNode->requestList) {
                RequestInfo *requestInfo = LIST_ENTRY(item, RequestInfo, node);
                ListDelete(&requestInfo->node);
                ListAdd(&notifyList, &requestInfo->node);
            }
            break;
        }
    }
    ClearSendItemByConnId(connectionId);
    ClearReceiveQueueByConnId(connectionId);
    ReleaseConnectionRef(brNode);
    (void)pthread_mutex_unlock(&g_connectionLock);
    if (connectionId != -1) {
        NotifyDisconnect(&notifyList, connectionId, connectionInfo, value);
    }
}

static int32_t ReceivedHeadCheck(const ConnPktHead *head, BrConnectionInfo *conn)
{
    if (head->magic != 0xBABEFACE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ClientOnDataReceived] magic error 0x%x", head->magic);
        conn->recvPos = 0;
        return SOFTBUS_ERR;
    }

    if (head->len > (g_brBuffSize - sizeof(ConnPktHead))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
            "[ClientOnDataReceived]data too large . module=%d,seq=%lld, datalen=%d",
            head->module, head->seq, head->len);
        conn->recvPos = 0;
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ReceivedError(ReceiveItemStruct *recvItem, char *dataCopy,
    const char *bufHead, const ConnPktHead  *head, int32_t sendToManagerLen)
{
    if (recvItem == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc recvItem fail");
        if (dataCopy != NULL) {
            SoftBusFree(dataCopy);
        }
        return SOFTBUS_ERR;
    }
    if (dataCopy == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc dataCopy fail");
        SoftBusFree(recvItem);
        return SOFTBUS_ERR;
    }
    if (memcpy_s(dataCopy, sendToManagerLen,
        bufHead, head->len + sizeof(ConnPktHead)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ReceivedError memcpy_s failed");
        SoftBusFree(dataCopy);
        SoftBusFree(recvItem);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}


static void InitRecvItemAndInsert(ReceiveItemStruct *recvItem, int32_t connectionId,
    const ConnPktHead *head, int32_t sendToManagerLen, const char *dataCopy)
{
    recvItem->connectionId = connectionId;
    recvItem->module = head->module;
    recvItem->seqNum = head->seq;
    recvItem->flag = head->flag;
    recvItem->dataLen = sendToManagerLen;
    recvItem->data = (uint8_t*)dataCopy;
    if (pthread_mutex_lock(&g_recvQueue.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "InitRecvItemAndInsert mutex failed");
        return;
    }
    if (recvItem->module == MODULE_DEVICE_AUTH) {
        ListAdd(&g_recvQueue.recvList, &recvItem->node);
    } else {
        ListTailInsert(&g_recvQueue.recvList, &recvItem->node);
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ClientOnDataReceived] connectionId=%d", connectionId);
    pthread_cond_signal(&g_recvQueue.cond);
    (void)pthread_mutex_unlock(&g_recvQueue.lock);
}

static void ClientOnDataReceived(int32_t socketFd, const char *buf, int32_t len)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ClientOnDataReceived] socketFd=%d,len=%d", socketFd, len);
    BrConnectionInfo *conn = NULL;
    (void)pthread_mutex_lock(&g_connectionLock);
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_conection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->socketFd == socketFd) {
            conn = itemNode;
            break;
        }
    }

    if (conn == NULL) {
        (void)pthread_mutex_unlock(&g_connectionLock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ClientOnDataReceived] not found socket=%d", socketFd);
        return;
    }

    char *bufHead = (char*)buf;
    int32_t bufLen = len;
    bool isCopy = false;
    if (conn->recvPos != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "[ClientOnDataReceived] recvPos=%d", conn->recvPos);
        (void)memcpy_s(conn->recvBuf + conn->recvPos, g_brBuffSize - conn->recvPos, buf, len);
        conn->recvPos += len;
        isCopy = true;
        bufHead = conn->recvBuf;
        bufLen = conn->recvPos;
    }
    // recv head
    if (bufLen < sizeof(ConnPktHead)) {
        if (!isCopy) {
            (void)memcpy_s(conn->recvBuf + conn->recvPos, g_brBuffSize - conn->recvPos, buf, len);
            conn->recvPos += len;
            isCopy = true;
        }
        (void)pthread_mutex_unlock(&g_connectionLock);
        return;
    }

    ConnPktHead *head = (ConnPktHead *)bufHead;
    if (ReceivedHeadCheck(head, conn) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&g_connectionLock);
        return;
    }

    if (head->len > (bufLen - sizeof(ConnPktHead))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
            "[ClientOnDataReceived] socket=%d , continue to recv", socketFd);
        if (!isCopy) {
            (void)memcpy_s(conn->recvBuf + conn->recvPos, g_brBuffSize - conn->recvPos, buf, len);
            conn->recvPos += len;
            isCopy = true;
        }
        (void)pthread_mutex_unlock(&g_connectionLock);
        return;
    }
    bool headtogether = false;
    int32_t sendToManagerLen = bufLen;
    if (head->len < (bufLen - sizeof(ConnPktHead))) {
        headtogether = true;
        sendToManagerLen = head->len + sizeof(ConnPktHead);
    }
    if (g_connectCallback != NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ClientOnDataReceived] socket=%d , ready to insert", socketFd);
        ReceiveItemStruct *recvItem = SoftBusMalloc(sizeof(ReceiveItemStruct));
        if (recvItem == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc failed");
            (void)pthread_mutex_unlock(&g_connectionLock);
            return;
        }
        char *dataCopy = SoftBusMalloc(sendToManagerLen);
        if (dataCopy == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc failed");
            SoftBusFree(recvItem);
            (void)pthread_mutex_unlock(&g_connectionLock);
            return;
        }
        if (ReceivedError(recvItem, dataCopy, bufHead, head, sendToManagerLen) != SOFTBUS_OK) {
            conn->recvPos = 0;
            (void)pthread_mutex_unlock(&g_connectionLock);
            return;
        }
        InitRecvItemAndInsert(recvItem, conn->connectionId, head, sendToManagerLen, dataCopy);
    }
    if (headtogether == false) {
        conn->recvPos = 0;
    } else {
        if (memmove_s(conn->recvBuf, g_brBuffSize,
            conn->recvBuf + sendToManagerLen, bufLen - sendToManagerLen) != EOK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memmove_s failed");
                (void)pthread_mutex_unlock(&g_connectionLock);
                return;
            }
        conn->recvPos = bufLen - sendToManagerLen;
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
}

static int32_t NotifyServerConn(int connectionId, const BrConnectionInfo *conn)
{
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    ConnectionInfo connectionInfo;
    connectionInfo.isAvailable = 1;
    connectionInfo.isServer = conn->sideType;
    connectionInfo.type = CONNECT_BR;
    if (strncpy_s(connectionInfo.info.brInfo.brMac,
        BT_MAC_LEN, conn->mac, sizeof(conn->mac)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "NotifyServerConn scpy error");
        (void)pthread_mutex_unlock(&g_connectionLock);
        return SOFTBUS_ERR;
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    g_connectCallback->OnConnected(connectionId, &connectionInfo);
    return SOFTBUS_OK;
}

static void ServerOnBrConnect(int32_t type, int32_t socketFd, int32_t value)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[new connection, socket = %d", value);
    (void)pthread_mutex_lock(&g_connectionLock);
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_conection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (value == itemNode->socketFd) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "Serviceconnection exit, socketFd=%d", socketFd);
            (void)pthread_mutex_unlock(&g_connectionLock);
            return;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    BrConnectionInfo *newConnectionInfo = CreateBrconnectionNode(false);
    if (newConnectionInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[service node create fail]");
        g_sppDriver->CloseClient(value);
        return;
    }
    RequestInfo *requestInfo = SoftBusCalloc(sizeof(RequestInfo));
    if (requestInfo == NULL) {
        ReleaseBrconnectionNode(newConnectionInfo);
        g_sppDriver->CloseClient(value);
        return;
    }
    ListInit(&requestInfo->node);
    ListAdd(&newConnectionInfo->requestList, &requestInfo->node);
    BluetoothRemoteDevice* info  = NULL;
    g_sppDriver->GetRemoteDeviceInfo(value, info);
    if (ConvertBtMacToStr(newConnectionInfo->mac, BT_MAC_LEN, (uint8_t *)info->mac, BT_ADDR_LEN_RFCOM) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "convert bt mac to str fail");
        ReleaseBrconnectionNode(newConnectionInfo);
        g_sppDriver->CloseClient(value);
        return;
    }
    newConnectionInfo->socketFd = value;
    newConnectionInfo->state = BR_CONNECTION_STATE_CONNECTED;
    newConnectionInfo->sideType = BR_SERVICE_TYPE;
    int connectionId = newConnectionInfo->connectionId;
    ListAdd(&g_conection_list, &newConnectionInfo->node);
    if (NotifyServerConn(connectionId, newConnectionInfo) != SOFTBUS_OK) {
        ReleaseBrconnectionNode(newConnectionInfo);
        g_sppDriver->CloseClient(value);
    }
    return;
}

static void ServerOnBrDisconnect(int32_t socketFd, int32_t value)
{
    ClientOnBrDisconnect(socketFd, value);
}

static void ServerOnDataReceived(int32_t socketFd, const char *buf, int32_t len)
{
    ClientOnDataReceived(socketFd, buf, len);
}

static void ServerOnEvent(int32_t type, int32_t socketFd, int32_t value)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ClientOnEvent] socketFd=%d", socketFd);
    if (type == SPP_EVENT_TYPE_CONNECTED) {
        ServerOnBrConnect(type, socketFd, value);
    } else if (type == SPP_EVENT_TYPE_DISCONNECTED) {
        ServerOnBrDisconnect(socketFd, value);
    }
}

static int32_t GetPriority(int32_t flag)
{
    int priority;
    switch (flag) {
        case CONN_HIGH: {
            priority = PRIORITY_HIGH;
            break;
        }
        case CONN_MIDDLE: {
            priority = PRIORITY_MID;
            break;
        }
        case CONN_LOW: {
            priority = PRIORITY_LOW;
            break;
        }
        default:
            priority = PRIORITY_DAF;
            break;
    }
    return priority;
}

static int32_t CheckSendQueueLength(void)
{
    int totalSendNum = 0;
    ListNode *sendItemNode = NULL;
    if (pthread_mutex_lock(&g_dataQueue.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "CheckSendQueueLength mutex failed");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH(sendItemNode, &g_dataQueue.sendList) {
        totalSendNum++;
    }
    (void)pthread_mutex_unlock(&g_dataQueue.lock);
    if (totalSendNum > g_brSendQueueMaxLen) {
        return SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL;
    }
    return SOFTBUS_OK;
}

static DataPidQueueStruct *CreatNewPidNode(int pid)
{
    DataPidQueueStruct *pidQueue = SoftBusCalloc(sizeof(DataPidQueueStruct));
    if (pidQueue == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "PostBytes CreatNewPidNode fail");
        return NULL;
    }
    ListInit(&pidQueue->node);
    pidQueue->pid = pid;
    ListTailInsert(&g_dataQueue.pidList, &pidQueue->node);
    return pidQueue;
}

static int32_t CreateNewSendItem(int pid, int flag, int connectionId, int len, const char *data)
{
    SendItemStruct *sendItem = SoftBusCalloc(sizeof(SendItemStruct));
    if (sendItem == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "PostBytes CreateNewSendItem fail");
        return SOFTBUS_ERR;
    }
    ListInit(&sendItem->node);
    sendItem->pid = pid;
    sendItem->priority = GetPriority(flag);
    sendItem->connectionId = connectionId;
    sendItem->dataLen = len;
    sendItem->data = (char*)data;

    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    SendItemStruct *sendItemInsert = NULL;
    int lastInsertFlag = false;
    LIST_FOR_EACH_SAFE(item, nextItem, &g_dataQueue.sendList) {
        sendItemInsert = LIST_ENTRY(item, SendItemStruct, node);
        if (sendItemInsert->pid == pid && sendItemInsert->priority < sendItem->priority) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendItem ListAdd");
            ListNode *sendItemNode = item->prev;
            ListAdd(sendItemNode, &sendItem->node);
            lastInsertFlag = true;
            break;
        }
    }
    if (lastInsertFlag != true) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendItem ListTailInsert");
        ListTailInsert(&g_dataQueue.sendList, &sendItem->node);
    }
    return SOFTBUS_OK;
}

static int32_t PostBytes(uint32_t connectionId, const char *data, int32_t len, int32_t pid, int32_t flag)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "PostBytes connectionId=%u,pid=%d,len=%d flag=%d", connectionId, pid, len, flag);
    (void)pthread_mutex_lock(&g_connectionLock);
    if (CheckSendQueueLength() != SOFTBUS_OK) {
        SoftBusFree((void*)data);
        (void)pthread_mutex_unlock(&g_connectionLock);
        return SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL;
    }
    BrConnectionInfo *conn = GetConnectionRef(connectionId);
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "PostBytes connectionId=%u not found", connectionId);
        SoftBusFree((void*)data);
        (void)pthread_mutex_unlock(&g_connectionLock);
        return SOFTBUS_BRCONNECTION_POSTBYTES_ERROR;
    }

    (void)pthread_mutex_lock(&g_dataQueue.lock);
    DataPidQueueStruct *pidQueue = NULL;
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_dataQueue.pidList) {
        DataPidQueueStruct *itemNode = LIST_ENTRY(item, DataPidQueueStruct, node);
        if (itemNode->pid == pid) {
            pidQueue = itemNode;
            break;
        }
    }
    if (pidQueue == NULL) {
        pidQueue = CreatNewPidNode(pid);
        if (pidQueue == NULL) {
            (void)pthread_mutex_unlock(&g_connectionLock);
            SoftBusFree((void*)data);
            (void)pthread_mutex_unlock(&g_dataQueue.lock);
            return SOFTBUS_BRCONNECTION_POSTBYTES_ERROR;
        }
    }

    pidQueue->itemCount++;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "PostBytes pidQueue count=%d", pidQueue->itemCount);
    if (CreateNewSendItem(pid, flag, connectionId, len, data) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&g_connectionLock);
        SoftBusFree((void*)data);
        SoftBusFree(pidQueue);
        (void)pthread_mutex_unlock(&g_dataQueue.lock);
        return SOFTBUS_BRCONNECTION_POSTBYTES_ERROR;
    }

    (void)pthread_mutex_unlock(&g_connectionLock);
    pthread_cond_broadcast(&g_dataQueue.cond);
    (void)pthread_mutex_unlock(&g_dataQueue.lock);
    return SOFTBUS_OK;
}


static void FreeSendItem(SendItemStruct *sendItem)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "FreeSendItem");
    if (sendItem == NULL) {
        return;
    }
    if (sendItem->data != NULL) {
        SoftBusFree(sendItem->data);
    }
    SoftBusFree(sendItem);
}


static void ClearDataPidByPid(int32_t pid)
{
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    LIST_FOR_EACH_SAFE(item, nextItem, &g_dataQueue.pidList) {
        DataPidQueueStruct *itemNode = LIST_ENTRY(item, DataPidQueueStruct, node);
        if (itemNode->pid == pid) {
            ListDelete(item);
            SoftBusFree(itemNode);
        }
    }
}

static void ClearSendItemByConnId(uint32_t connectionId)
{
    if (pthread_mutex_lock(&g_dataQueue.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ClearSendItemByConnId mutex failed");
        return;
    }
    ListNode *sendItemNode = NULL;
    ListNode *nextItem = NULL;
    SendItemStruct *sendItem = NULL;
    LIST_FOR_EACH_SAFE(sendItemNode, nextItem, &g_dataQueue.sendList) {
        sendItem = LIST_ENTRY(sendItemNode, SendItemStruct, node);
        if (sendItem->connectionId == connectionId) {
            ClearDataPidByPid(sendItem->pid);
            ListDelete(sendItemNode);
            FreeSendItem(sendItem);
        }
    }
    (void)pthread_mutex_unlock(&g_dataQueue.lock);
}

static int32_t SendData(SendItemStruct *sendItem)
{
    BrConnectionInfo *brConnInfo = NULL;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendData");
    (void)pthread_mutex_lock(&g_connectionLock);
    ListNode *item = NULL;
    int32_t socketFd = -1;
    LIST_FOR_EACH(item, &g_conection_list) {
        brConnInfo = LIST_ENTRY(item, BrConnectionInfo, node);
        if (brConnInfo->connectionId == sendItem->connectionId) {
            socketFd = brConnInfo->socketFd;
        }
    }

    if (socketFd == -1) {
        (void)pthread_mutex_unlock(&g_connectionLock);
        return SOFTBUS_ERR;
    }
    int32_t writeRet = -1;
    int freeLock = false;

    int32_t templen = sendItem->dataLen;
    char *sendData = sendItem->data;
    while (templen > 0) {
        (void)pthread_mutex_lock(&brConnInfo->lock);
        while (brConnInfo->conGestState == BT_RFCOM_CONGEST_ON &&
            brConnInfo->state == BR_CONNECTION_STATE_CONNECTED) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "wait congest");
            (void)pthread_mutex_unlock(&g_connectionLock);
            freeLock = true;
            pthread_cond_wait(&brConnInfo->congestCond, &brConnInfo->lock);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "free congest");
            break;
        }
        (void)pthread_mutex_unlock(&brConnInfo->lock);

        int32_t sendlenth = templen;
        if (sendlenth > g_brSendPeerLen) {
            sendlenth = g_brSendPeerLen;
        }
        writeRet = g_sppDriver->Write(socketFd, sendItem->data, sendlenth);
        sendItem->data += sendlenth;
        templen -= sendlenth;
    }
    sendItem->data = sendData;
    if (freeLock != true) {
        (void)pthread_mutex_unlock(&g_connectionLock);
    }
    return writeRet;
}

void *SendHandlerLoop(void *arg)
{
    while (1) {
        (void)pthread_mutex_lock(&g_dataQueue.lock);
        if (IsListEmpty(&g_dataQueue.sendList)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendHandlerLoop empty");
            pthread_cond_wait(&g_dataQueue.cond, &g_dataQueue.lock);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "start SendHandlerLoop");
            (void)pthread_mutex_unlock(&g_dataQueue.lock);
            continue;
        }
        ListNode *item = NULL;
        LIST_FOR_EACH(item, &g_dataQueue.pidList) {
            DataPidQueueStruct *itemNode = LIST_ENTRY(item, DataPidQueueStruct, node);
            ListDelete(item);
            itemNode->itemCount--;
            sendPid = itemNode->pid;
            if (itemNode->itemCount == 0) {
                SoftBusFree(itemNode);
            } else {
                ListTailInsert(&g_dataQueue.pidList, &itemNode->node);
            }
            break;
        }

        ListNode *sendItemNode = NULL;
        SendItemStruct *sendItem = NULL;
        LIST_FOR_EACH(sendItemNode, &g_dataQueue.sendList) {
            sendItem = LIST_ENTRY(sendItemNode, SendItemStruct, node);
            if (sendItem->pid == sendPid) {
                ListDelete(sendItemNode);
                break;
            }
        }
        if (sendItem == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendItem fail");
            continue;
        }
        (void)pthread_mutex_unlock(&g_dataQueue.lock);
        if (SendData(sendItem) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendItem fail");
        }
        FreeSendItem(sendItem);
    }
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
            BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
            if (itemNode->connectionId == connectionId) {
                if (itemNode->state == BR_CONNECTION_STATE_CLOSING) {
                    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "NOTIFY_CHANGE");
                    itemNode->state = BR_CONNECTION_STATE_CONNECTED;
                }
                break;
            }
        }
        (void)pthread_mutex_unlock(&g_connectionLock);
    }
}

void *RecvHandlerLoop(void *arg)
{
    while (1) {
        (void)pthread_mutex_lock(&g_recvQueue.lock);
        if (IsListEmpty(&g_recvQueue.recvList)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RecvHandlerLoop empty");
            pthread_cond_wait(&g_recvQueue.cond, &g_recvQueue.lock);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "Recv recvQueueCond");
            (void)pthread_mutex_unlock(&g_recvQueue.lock);
            continue;
        }

        ListNode *recvItemNode = NULL;
        ReceiveItemStruct *recvItem = NULL;
        LIST_FOR_EACH(recvItemNode, &g_recvQueue.recvList) {
            recvItem = LIST_ENTRY(recvItemNode, ReceiveItemStruct, node);
            ListDelete(recvItemNode);
            break;
        }
        (void)pthread_mutex_unlock(&g_recvQueue.lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RecvHandlerLoop OnDataReceived");
        if (recvItem->module == MODULE_CONNECTION) {
            cJSON *data = NULL;
            data = cJSON_Parse((char *)(recvItem->data + sizeof(ConnPktHead)));
            if (data == NULL) {
                SoftBusFree(recvItem->data);
                SoftBusFree(recvItem);
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[receive data invalid]");
                continue;
            }
            RecvConnectedComd(recvItem->connectionId, (const cJSON*)data);
            cJSON_Delete(data);
        } else {
            if (g_connectCallback != NULL) {
            g_connectCallback->OnDataReceived(recvItem->connectionId, (ConnModule)recvItem->module, recvItem->seqNum,
                (char*)recvItem->data, recvItem->dataLen);
            }
        }
        SoftBusFree(recvItem->data);
        SoftBusFree(recvItem);
    }
}

static void ClearReceiveQueueByConnId(uint32_t connectionId)
{
    if (pthread_mutex_lock(&g_recvQueue.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ClearReceiveQueueByConnId mutex failed");
        return;
    }
    ListNode *recvItemNode = NULL;
    ListNode *nextItem = NULL;
    ReceiveItemStruct *recvItem = NULL;
    LIST_FOR_EACH_SAFE(recvItemNode, nextItem, &g_recvQueue.recvList) {
        recvItem = LIST_ENTRY(recvItemNode, ReceiveItemStruct, node);
        if (recvItem->connectionId == connectionId) {
            ListDelete(recvItemNode);
            SoftBusFree(recvItem->data);
            SoftBusFree(recvItem);
        }
    }
    (void)pthread_mutex_unlock(&g_recvQueue.lock);
}

static int32_t DisconnectDevice(uint32_t connectionId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[DisconnectDevice]");
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "DisconnectDevice mutex failed");
        return SOFTBUS_ERR;
    }
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    int getConnectionId = -1;
    LIST_FOR_EACH_SAFE(item, nextItem, &g_conection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->connectionId == connectionId) {
            getConnectionId = itemNode->connectionId;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    if (getConnectionId == -1) {
        return SOFTBUS_BRCONNECTION_DISCONNECT_NOTFIND;
    }
    (void)PackRequest(CONNECT_REF_DECRESE, getConnectionId);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[DisconnectDevice over]");
    return SOFTBUS_OK;
}

static int32_t DisconnectDeviceNow(const ConnectOption *option)
{
    int32_t ret = (int32_t)SOFTBUS_ERR;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[DisconnectDeviceByOption]");
    if (option == NULL || option->type != CONNECT_BR) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "option check fail");
        return ret;
    }
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "DisconnectDevice mutex failed");
        return ret;
    }
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    ConnectionInfo connectionInfo;
    LIST_FOR_EACH_SAFE(item, nextItem, &g_conection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (memcmp(itemNode->mac, option->info.brOption.brMac, sizeof(itemNode->mac)) == 0) {
            if (!IsListEmpty(&g_dataQueue.sendList)) {
                osDelay(DISCONN_DELAY_TIME);
            }
            ret = g_sppDriver->CloseClient(itemNode->socketFd);
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return ret;
}

static void InitDataQueue(DataQueueStruct *dataQueue)
{
    ListInit(&dataQueue->sendList);
    ListInit(&dataQueue->pidList);
    pthread_mutex_init(&dataQueue->lock, NULL);
    pthread_cond_init(&dataQueue->cond, NULL);

    pthread_t tid;
    pthread_attr_t threadAttr;
    pthread_attr_init(&threadAttr);
    pthread_attr_setstacksize(&threadAttr, BR_SEND_THREAD_STACK);
    if (pthread_create(&tid, &threadAttr, SendHandlerLoop, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create DeathProcTask failed");
    }
}

static void InitRecvQueue(RecvQueueStruct *recvQueue)
{
    ListInit(&recvQueue->recvList);
    pthread_mutex_init(&recvQueue->lock, NULL);
    pthread_cond_init(&recvQueue->cond, NULL);

    pthread_t tid;
    pthread_attr_t threadAttr;
    pthread_attr_init(&threadAttr);
    pthread_attr_setstacksize(&threadAttr, BR_RECE_THREAD_STACK);
    if (pthread_create(&tid, &threadAttr, RecvHandlerLoop, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create DeathProcTask failed");
    }
}

static int32_t StartLocalListening(const LocalListenerInfo *info)
{
    if (g_sppDriver == NULL) {
        return SOFTBUS_ERR;
    }
    int32_t socketId = g_sppDriver->OpenSppServer(NULL, UUID, 0);
    g_sppDriver->Accept(socketId, (const SppSocketEventCallback*)&g_sppSocketServiceCallback);
    return SOFTBUS_OK;
}

static int32_t StopLocalListening(const LocalListenerInfo *info)
{
    if (g_sppDriver == NULL) {
        return SOFTBUS_ERR;
    }
    g_sppDriver->CloseServer(0);
    return SOFTBUS_OK;
}

static int32_t InitProperty()
{
    g_brBuffSize = INVALID_LENGTH;
    g_brSendPeerLen = INVALID_LENGTH;
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH,
        (unsigned char*)&g_brBuffSize, sizeof(g_brBuffSize)) != SOFTBUS_OK) {
        LOG_ERR("get br BuffSize fail");
    }
    LOG_INFO("br BuffSize is %u", g_brBuffSize);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN,
        (unsigned char*)&g_brSendPeerLen, sizeof(g_brSendPeerLen)) != SOFTBUS_OK) {
        LOG_ERR("get br SendPeerLen fail");
    }
    LOG_INFO("br SendPeerLen is %u", g_brSendPeerLen);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_BR_RECEIVE_MAX_LEN,
        (unsigned char*)&g_brSendQueueMaxLen, sizeof(g_brSendQueueMaxLen)) != SOFTBUS_OK) {
        LOG_ERR("get br SendQueueMaxLen fail");
    }
    LOG_INFO("br SendQueueMaxLen is %u", g_brSendQueueMaxLen);
    if (g_brBuffSize == INVALID_LENGTH || g_brBuffSize > MAX_BR_SIZE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot get brBuffSize");
        return SOFTBUS_ERR;
    }
    if (g_brSendPeerLen == INVALID_LENGTH || g_brSendPeerLen > MAX_BR_PEER_SIZE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot get brSendPeerLen");
        return SOFTBUS_ERR;
    }
    if (g_brSendQueueMaxLen == SOFTBUS_ERR || g_brSendQueueMaxLen > MAX_BR_PEER_SIZE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot get brSendQueueMaxLen");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

ConnectFuncInterface *ConnInitBr(const ConnectCallback *callback)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[InitBR]");
    if (InitProperty() != SOFTBUS_OK) {
        return NULL;
    }
    pthread_mutex_init(&g_connectionLock, NULL);
    InitDataQueue(&g_dataQueue);
    InitRecvQueue(&g_recvQueue);
    g_connectCallback = (ConnectCallback*)callback;
    g_sppDriver = InitSppSocketDriver();
    if (g_sppDriver != NULL) {
        g_sppDriver->Init(g_sppDriver);
    }
    return &g_brInterface;
}

static bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int *target)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item) || (item->valuedouble < 0)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (int)item->valuedouble;
    return true;
}

static bool AddNumberToJsonObject(cJSON *obj, const char * const string, int32_t num)
{
    if (obj == NULL || string == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "AddNumberToJsonObject fail");
        return false;
    }
    cJSON *item = cJSON_CreateNumber(num);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot create cJSON number object [%s]", string);
        return false;
    }
    if (!cJSON_AddItemToObject(obj, string, item)) {
        cJSON_Delete(item);
        return false;
    }
    return true;
}
