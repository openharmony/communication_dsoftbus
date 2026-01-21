/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "softbus_conn_general_connection.h"

#include <string.h>
#include <stdint.h>
#include "securec.h"

#include "ble_protocol_interface_factory.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_manager.h"
#include "bus_center_manager.h"

#define INVALID_UNDERLAY_HANDLE            (-1)
#define GENERAL_CONNECT_TIMEOUT_MILLIS     (10 * 1000)
#define GENERAL_CONNECT_DISCONNECT_DELAY   (100)

#define GENERAL_PSM                        (128)

#define GENERAL_PKGNAME_MAX_COUNT          (10)

static uint64_t g_seq = 0;

enum GeneralFeatureCapability {
    GENERAL_FEATURE_SUPPORT_COC = 1
};

typedef struct {
    SoftBusList *connections;
    SoftBusList *servers;
} GeneralManager;

enum GeneralMgrLooperMsg {
    GENERAL_MGR_MSG_MERGE_CMD,
    GENERAL_MGR_MSG_CONNECT_TIMEOUT,
    GENERAL_MGR_MSG_DISCONNECT_DELAY,
};

static void ConnReturnGeneralConnection(struct GeneralConnection **generalConnection);
struct GeneralConnection *GetConnectionByGeneralId(uint32_t generalId);
static void ConnRemoveGeneralConnection(struct GeneralConnection *generalConnection);
static void GeneralManagerMsgHandler(SoftBusMessage *msg);
static int GeneralCompareConnectionLooperEventFunc(const SoftBusMessage *msg, void *args);
static void MergeConnection(uint32_t generalId);
static void OnConnectTimeout(uint32_t generalId);
static void DisconnectDelay(uint32_t connectionId);

static void OnCommConnectSucc(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info);
static void OnCommConnectFail(uint32_t requestId, int32_t reason);

static GeneralConnectionListener g_generalConnectionListener;
static GeneralManager g_generalManager;

static SoftBusMutex g_requestIdLock;
static uint32_t g_requestId = 1;

static ConnectResult g_result = {
    .OnConnectSuccessed = OnCommConnectSucc,
    .OnConnectFailed = OnCommConnectFail,
};

static SoftBusHandlerWrapper g_generalManagerSyncHandler = {
    .handler = {
        .name = (char *)"GeneralManagerAsyncHandler",
        .HandleMessage = GeneralManagerMsgHandler,
        // assign when initiation
        .looper = NULL,
    },
    .eventCompareFunc = GeneralCompareConnectionLooperEventFunc,
};

static int GeneralCompareConnectionLooperEventFunc(const SoftBusMessage *msg, void *args)
{
    SoftBusMessage *ctx = (SoftBusMessage *)args;
    CONN_CHECK_AND_RETURN_RET_LOGE(msg->what == ctx->what, COMPARE_FAILED, CONN_BLE, "compare fail");
    switch (ctx->what) {
        case GENERAL_MGR_MSG_MERGE_CMD: {
            if (msg->arg1 == ctx->arg1) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        case GENERAL_MGR_MSG_CONNECT_TIMEOUT: {
            if (msg->arg1 == ctx->arg1) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        case GENERAL_MGR_MSG_DISCONNECT_DELAY: {
            if (msg->arg1 == ctx->arg1) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        default:
            break;
    }
    if (ctx->arg1 != 0) {
        CONN_LOGE(CONN_BLE,
            "context not use, what=%{public}d, arg1=%{public}" PRIu64 ", objIsNull=%{public}d",
            ctx->what, ctx->arg1, ctx->obj == NULL);
        return COMPARE_FAILED;
    }
    return COMPARE_SUCCESS;
}

static void GeneralManagerMsgHandler(SoftBusMessage *msg)
{
    CONN_CHECK_AND_RETURN_LOGW(msg != NULL, CONN_BLE, "msg is null");
    switch (msg->what) {
        case GENERAL_MGR_MSG_MERGE_CMD:
            MergeConnection((uint32_t)msg->arg1);
            break;
        case GENERAL_MGR_MSG_CONNECT_TIMEOUT:
            OnConnectTimeout((uint32_t)msg->arg1);
            break;
        case GENERAL_MGR_MSG_DISCONNECT_DELAY:
            DisconnectDelay((uint32_t)msg->arg1);
            break;
        default:
            CONN_LOGW(CONN_BLE, "unexpected msg, what=%{public}d", msg->what);
            break;
    }
}

static int32_t SendInner(OutData *outData, uint32_t underlayerHandle, int32_t module, int32_t pid)
{
    ConnPostData buff = {0};
    buff.seq = g_seq++;
    buff.flag = CONN_HIGH;
    buff.pid = pid;

    uint32_t size = ConnGetHeadSize();
    buff.len = outData->dataLen + size;
    buff.buf = (char *)SoftBusCalloc(buff.len);
    buff.module = module;
    if (buff.buf == NULL || memcpy_s(buff.buf + size, outData->dataLen, outData->data, outData->dataLen) != EOK) {
        SoftBusFree(buff.buf);
        CONN_LOGE(CONN_BLE, "malloc error");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = ConnPostBytes(underlayerHandle, &buff);
    if (ret < 0) {
        CONN_LOGE(CONN_BLE, "send fail, err=%{public}d, underlayHandle=%{public}u", ret, underlayerHandle);
    }
    return ret;
}

static OutData *PackData(struct GeneralConnection *generalConnection, const uint8_t *data, uint32_t dataLen)
{
    OutData *outData = (OutData *)SoftBusCalloc(sizeof(OutData));
    CONN_CHECK_AND_RETURN_RET_LOGE(outData != NULL, NULL, CONN_BLE, "malloc outData err");
    outData->dataLen = GENERAL_CONNECTION_HEADER_SIZE + dataLen;
    outData->data = (uint8_t *)SoftBusCalloc(outData->dataLen);
    if (outData->data == NULL) {
        CONN_LOGE(CONN_BLE, "malloc outData->data err");
        SoftBusFree(outData);
        return NULL;
    }
    GeneralConnectionHead *header = (GeneralConnectionHead *)outData->data;
    header->headLen = GENERAL_CONNECTION_HEADER_SIZE;
    header->localId = generalConnection->generalId;
    header->peerId = generalConnection->peerGeneralId;
    header->msgType = GENERAL_CONNECTION_MSG_TYPE_NORMAL;
    PackGeneralHead(header);
    if (memcpy_s(outData->data + GENERAL_CONNECTION_HEADER_SIZE,
        outData->dataLen - GENERAL_CONNECTION_HEADER_SIZE, data, dataLen) != EOK) {
        FreeOutData(outData);
        outData = NULL;
    }
    return outData;
}

static void ConnReturnGeneralConnection(struct GeneralConnection **generalConnection)
{
    CONN_CHECK_AND_RETURN_LOGE(generalConnection != NULL, CONN_BLE, "connection is null");
    CONN_CHECK_AND_RETURN_LOGE(*generalConnection != NULL, CONN_BLE, "*connection is null");

    struct GeneralConnection *underlayer = *generalConnection;
    underlayer->dereference(underlayer);
    *generalConnection = NULL;
}

struct GeneralConnection *GetConnectionByGeneralId(uint32_t generalId)
{
    int32_t ret = SoftBusMutexLock(&g_generalManager.connections->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, CONN_BLE, "lock fail");
    struct GeneralConnection *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_generalManager.connections->list, struct GeneralConnection, node) {
        if (it->generalId == generalId) {
            it->reference(it);
            (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);
            return it;
        }
    }
    (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);
    return NULL;
}

static void ConnRemoveGeneralConnection(struct GeneralConnection *generalConnection)
{
    CONN_CHECK_AND_RETURN_LOGE(generalConnection != NULL, CONN_BLE, "connection is null");
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_generalManager.connections->lock) == SOFTBUS_OK, CONN_BLE,
        "lock fail");

    struct GeneralConnection *it = NULL;
    bool exist = false;
    LIST_FOR_EACH_ENTRY(it, &g_generalManager.connections->list, struct GeneralConnection, node) {
        if (it->generalId == generalConnection->generalId) {
            exist = true;
            break;
        }
    }
    if (exist) {
        ListDelete(&generalConnection->node);
        ConnReturnGeneralConnection(&generalConnection);
    } else {
        CONN_LOGW(CONN_BLE, "connection not exist, generalId=%{public}u", generalConnection->generalId);
    }
    (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);
}

struct GeneralConnection *GetGeneralConnectionByReqId(uint32_t reqId)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_generalManager.connections->lock) == SOFTBUS_OK, NULL, CONN_BLE,
        "lock fail");
    struct GeneralConnection *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_generalManager.connections->list, struct GeneralConnection, node) {
        if (it->requestId == reqId) {
            it->reference(it);
            (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);
            return it;
        }
    }
    (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);
    return NULL;
}

struct GeneralConnection *GetGeneralConnectionByParam(const char *pkgName, int32_t pid)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_generalManager.connections->lock) == SOFTBUS_OK, NULL, CONN_BLE,
        "lock fail");
    struct GeneralConnection *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_generalManager.connections->list, struct GeneralConnection, node) {
        if (StrCmpIgnoreCase(it->info.pkgName, pkgName) == 0 && it->info.pid == pid) {
            it->reference(it);
            (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);
            return it;
        }
    }
    (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);
    return NULL;
}

static int32_t GeneralSendResetMessage(struct GeneralConnection *generalConnection)
{
    GeneralConnectionInfo info = { { 0 } };
    info.localId = generalConnection->generalId;
    info.peerId = generalConnection->peerGeneralId;
    OutData *data = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_RESET);
    CONN_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_CONN_GENERAL_PACK_ERROR, CONN_BLE,
        "pack data fail, generalId=%{public}u", generalConnection->generalId);
    CONN_LOGI(CONN_BLE, "send reset msg, generalId=%{public}u", generalConnection->generalId);
    int32_t ret = SendInner(data, generalConnection->underlayerHandle, MODULE_BLE_GENERAL, 0);
    FreeOutData(data);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "send fail, generalId=%{public}u, err=%{public}d", generalConnection->generalId, ret);
        ConnDisconnectDevice(generalConnection->underlayerHandle);
        return ret;
    }
    if (generalConnection->isClient &&
        ConnPostMsgToLooper(&g_generalManagerSyncHandler, GENERAL_MGR_MSG_DISCONNECT_DELAY,
            generalConnection->underlayerHandle, 0, NULL, GENERAL_CONNECT_DISCONNECT_DELAY) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "post msg fail");
        return SOFTBUS_CONN_GENERAL_POST_MSG_FAILED;
    }
    return SOFTBUS_OK;
}

static Server *NewServerNode(const GeneralConnectionParam *param)
{
    Server *nameNode = (Server *)SoftBusCalloc(sizeof(Server));
    CONN_CHECK_AND_RETURN_RET_LOGE(nameNode != NULL, NULL, CONN_BLE, "nameNode is null");
    ListInit(&nameNode->node);
    if ((strncpy_s(nameNode->info.bundleName, BUNDLE_NAME_MAX, param->bundleName, BUNDLE_NAME_MAX - 1) != EOK) ||
        (strncpy_s(nameNode->info.name, GENERAL_NAME_LEN, param->name, GENERAL_NAME_LEN - 1) != EOK) ||
        (strncpy_s(nameNode->info.pkgName, PKG_NAME_SIZE_MAX, param->pkgName, PKG_NAME_SIZE_MAX - 1) != EOK)) {
        CONN_LOGE(CONN_BLE, "strcpy fail");
        SoftBusFree(nameNode);
        return NULL;
    }
    nameNode->info.pid = param->pid;
    return nameNode;
}

static void FreeServerNode(Server **nameNode)
{
    SoftBusFree(*nameNode);
    *nameNode = NULL;
}

static void ClearAllGeneralConnection(const char *pkgName, int32_t pid)
{
    CONN_LOGW(CONN_BLE, "clean up connections");
    CONN_CHECK_AND_RETURN_LOGE(pkgName != NULL, CONN_BLE, "pkgName is null");
    CONN_CHECK_AND_RETURN_LOGE((SoftBusMutexLock(&g_generalManager.servers->lock)) == SOFTBUS_OK, CONN_BLE,
        "lock servers fail");
    Server *serverIt = NULL;
    Server *serverNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(serverIt, serverNext, &g_generalManager.servers->list, Server, node) {
        if (StrCmpIgnoreCase(serverIt->info.pkgName, pkgName) == 0 && serverIt->info.pid == pid) {
            ListDelete(&serverIt->node);
            FreeServerNode(&serverIt);
        }
    }
    (void)SoftBusMutexUnlock(&g_generalManager.servers->lock);

    ListNode waitNotifyDisconnect = {0};
    ListInit(&waitNotifyDisconnect);
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_generalManager.connections->lock) == SOFTBUS_OK, CONN_BLE,
        "lock fail");
    struct GeneralConnection *it = NULL;
    struct GeneralConnection *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_generalManager.connections->list, struct GeneralConnection, node) {
        if (StrCmpIgnoreCase(it->info.pkgName, pkgName) == 0 && it->info.pid == pid) {
            ListDelete(&it->node);
            ListAdd(&waitNotifyDisconnect, &it->node);
        }
    }
    (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);
    
    struct GeneralConnection *item = NULL;
    struct GeneralConnection *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &waitNotifyDisconnect, struct GeneralConnection, node) {
        ListDelete(&item->node);
        GeneralSendResetMessage(item);
        ConnReturnGeneralConnection(&item);
    }
}

static int32_t GeneralSendMergeMessage(struct GeneralConnection *generalConnection, uint32_t updateHandle)
{
    GeneralConnectionInfo info = { { 0 } };
    info.localId = generalConnection->generalId;
    info.peerId = generalConnection->peerGeneralId;
    info.updateHandle = updateHandle;
    OutData *data = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_MERGE);
    CONN_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_CONN_GENERAL_PACK_ERROR, CONN_BLE,
        "pack data fail, generalId=%{public}u", generalConnection->generalId);
    int32_t ret = SendInner(data, generalConnection->underlayerHandle, MODULE_BLE_GENERAL, 0);
    FreeOutData(data);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_CONN_GENERAL_PACK_ERROR, CONN_BLE,
        "send fail, generalId=%{public}u, err=%{public}d", generalConnection->generalId, ret);
    return ret;
}

static int32_t GeneralSessionNegotiation(
    struct GeneralConnection *generalConnection, int32_t ackStatus, GeneralConnectionMsgType type)
{
    GeneralConnectionInfo info = { { 0 } };
    if (strcpy_s(info.name, GENERAL_NAME_LEN, generalConnection->info.name) != EOK ||
        strcpy_s(info.bundleName, BUNDLE_NAME_MAX, generalConnection->info.bundleName) != EOK) {
            CONN_LOGE(CONN_BLE, "copy address fail, generalId=%{public}u", generalConnection->generalId);
        return SOFTBUS_STRCPY_ERR;
    }
    info.ackStatus = ackStatus;
    info.localId = generalConnection->generalId;
    info.peerId = generalConnection->peerGeneralId;
    info.abilityBitSet = generalConnection->abilityBitSet;
    OutData *data = GeneralConnectionPackMsg(&info, type);
    CONN_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_CONN_GENERAL_PACK_ERROR, CONN_BLE,
        "pack data fail, generalId=%{public}u", generalConnection->generalId);
    CONN_LOGI(CONN_BLE, "send session negotiation msg, generalId=%{public}u", generalConnection->generalId);
    int32_t ret = SendInner(data, generalConnection->underlayerHandle, MODULE_BLE_GENERAL, 0);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "send fail, generalId=%{public}u, err=%{public}d", generalConnection->generalId, ret);
    }
    FreeOutData(data);
    return ret;
}

static int32_t StartConnConnectDevice(const char *addr,
    BleProtocolType protocol, ConnectResult *result, uint32_t requestId)
{
    // if protocol is not supported, BLE_GATT will be used by default.
    protocol = ConnBleGetUnifyInterface(protocol) == NULL ? BLE_GATT : protocol;
    ConnectOption option = {
        .type = CONNECT_BLE,
        .bleOption.protocol = protocol,
        .bleOption.fastestConnectEnable = true,
        .bleOption.psm = GENERAL_PSM,
        .bleOption.connectTimeoutMs = GENERAL_CONNECT_TIMEOUT_MILLIS,
    };
    if (strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, addr) != EOK) {
        CONN_LOGE(CONN_BLE, "copy mac fail");
        return SOFTBUS_STRCPY_ERR;
    }
    int32_t ret = ConnConnectDevice(&option, requestId, result);
    CONN_LOGI(CONN_BLE, "connect device, ret=%{public}d, reqId=%{public}u", ret, requestId);
    return ret;
}

static int32_t SetConnectionDeviceId(struct GeneralConnection *generalConnection)
{
    ConnBleConnection *bleConnection = ConnBleGetConnectionById(generalConnection->underlayerHandle);
    CONN_CHECK_AND_RETURN_RET_LOGE(bleConnection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "can not get ble connection, generalId=%{public}u, underlayerHandle=%{public}u",
        generalConnection->generalId, generalConnection->underlayerHandle);
    ConnBleCancelIdleTimeout(bleConnection);
    ConnBleFeatureBitSet featureBitSet = bleConnection->featureBitSet;
    bool isSupportNetWorkIdExchange =
        (featureBitSet & (1 << BLE_FEATURE_SUPPORT_SUPPORT_NETWORKID_BASICINFO_EXCAHNGE)) != 0;
    generalConnection->isSupportNetWorkIdExchange = (bleConnection->protocol == BLE_COC || isSupportNetWorkIdExchange);
    int32_t ret = EOK;
    if (generalConnection->isSupportNetWorkIdExchange) {
        ret = strcpy_s(generalConnection->networkId, NETWORK_ID_BUF_LEN, bleConnection->networkId);
    } else {
        ret = strcpy_s(generalConnection->udid, UDID_BUF_LEN, bleConnection->udid);
    }
    if (ret != EOK) {
        CONN_LOGE(CONN_BLE, "server copy networkId fail, generalId=%{public}u", generalConnection->generalId);
    }
    ret = memcpy_s(generalConnection->addr, BT_MAC_LEN, bleConnection->addr, BT_MAC_LEN);
    ConnBleReturnConnection(&bleConnection);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, CONN_BLE,
        "copy mac fail, err=%{public}d", ret);
    return SOFTBUS_OK;
}

static void OnCommConnectSucc(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info)
{
    (void)info;
    struct GeneralConnection *generalConnection = GetGeneralConnectionByReqId(requestId);
    CONN_CHECK_AND_RETURN_LOGE(generalConnection != NULL, CONN_BLE, "get connection fail");
    int32_t status = SOFTBUS_OK;
    do {
        if (SoftBusMutexLock(&generalConnection->lock) != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "lock fail, generalId=%{public}u", generalConnection->generalId);
            status = SOFTBUS_LOCK_ERR;
            break;
        }
        generalConnection->underlayerHandle = connectionId;
        (void)SoftBusMutexUnlock(&generalConnection->lock);
        status = SetConnectionDeviceId(generalConnection);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE,
                "can not get deviceId, generalId=%{public}u, underlayerHandle=%{public}u, err=%{public}d",
                generalConnection->generalId, connectionId, status);
            break;
        }
        CONN_LOGI(CONN_BLE,
            "on connect succ, begin handshake, generalId=%{public}u, underlayerHandle=%{public}u",
            generalConnection->generalId, connectionId);
        status = GeneralSessionNegotiation(generalConnection, 0, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    } while (false);
    if (status != SOFTBUS_OK) {
        ConnRemoveMsgFromLooper(&g_generalManagerSyncHandler, GENERAL_MGR_MSG_CONNECT_TIMEOUT,
            generalConnection->generalId, 0, NULL);
        g_generalConnectionListener.onConnectFailed(&generalConnection->info,
            generalConnection->generalId, status);
        ConnDisconnectDevice(generalConnection->underlayerHandle);
        ConnRemoveGeneralConnection(generalConnection);
    }
    ConnReturnGeneralConnection(&generalConnection);
}

static uint32_t GenerateRequestId(void)
{
    int32_t ret = SoftBusMutexLock(&g_requestIdLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, g_requestId, CONN_BLE, "lock fail");
    uint32_t reqId = g_requestId++;
    (void)SoftBusMutexUnlock(&g_requestIdLock);
    return reqId;
}

static void OnCommConnectFail(uint32_t requestId, int32_t reason)
{
    struct GeneralConnection *connection = GetGeneralConnectionByReqId(requestId);
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_BLE, "get connection fail");
    CONN_LOGE(CONN_BLE,
        "on connect fail, generalId=%{public}u, reason=%{public}d",
        connection->generalId, reason);
    ConnRemoveMsgFromLooper(&g_generalManagerSyncHandler, GENERAL_MGR_MSG_CONNECT_TIMEOUT,
        connection->generalId, 0, NULL);
    if (connection->protocol == BLE_GATT) {
        g_generalConnectionListener.onConnectFailed(&connection->info, connection->generalId, reason);
        ConnRemoveGeneralConnection(connection);
        ConnReturnGeneralConnection(&connection);
        return;
    }
    if (connection->protocol == BLE_COC) {
        CONN_LOGI(CONN_BLE,
            "connect fail, try to connect gatt, generalId=%{public}u", connection->generalId);
        int32_t ret = SoftBusMutexLock(&connection->lock);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "lock fail, error=%{public}d", ret);
            g_generalConnectionListener.onConnectFailed(&connection->info, connection->generalId, ret);
            ConnRemoveGeneralConnection(connection);
            ConnReturnGeneralConnection(&connection);
            return;
        }
        connection->protocol = BLE_GATT;
        connection->requestId = GenerateRequestId();
        (void)SoftBusMutexUnlock(&connection->lock);
        ret = StartConnConnectDevice(connection->addr, BLE_GATT, &g_result, connection->requestId);
        if (ret != SOFTBUS_OK) {
            g_generalConnectionListener.onConnectFailed(&connection->info, connection->generalId, ret);
            ConnRemoveGeneralConnection(connection);
            ConnReturnGeneralConnection(&connection);
            return;
        }
    }
    ConnReturnGeneralConnection(&connection);
}

static void UpdateConnectionState(struct GeneralConnection *generalConnection,
    enum GeneralConnState expectedState, enum GeneralConnState nextState)
{
    int32_t ret = SoftBusMutexLock(&generalConnection->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_BLE, "lock fail");
    if (generalConnection->state != expectedState) {
        CONN_LOGW(CONN_BLE,
            "unexpected state, actualState=%{public}d, expectedState=%{public}d, nextState=%{public}d",
            generalConnection->state, expectedState, nextState);
        (void)SoftBusMutexUnlock(&generalConnection->lock);
        return;
    }
    generalConnection->state = nextState;
    (void)SoftBusMutexUnlock(&generalConnection->lock);
}

static uint32_t AllocateGeneralIdUnsafe(void)
{
    static uint16_t nextId = 0;
    uint32_t generalId = (CONNECT_BLE_GENERAL << CONNECT_TYPE_SHIFT) + (++nextId);
    struct GeneralConnection *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_generalManager.connections->list, struct GeneralConnection, node) {
        if (generalId == it->generalId) {
            return 0;
        }
    }
    return generalId;
}

static bool FindInfoFromServer(GeneralConnectionInfo *info, struct GeneralConnection *generalConnection)
{
    int32_t ret = SoftBusMutexLock(&g_generalManager.servers->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, false, CONN_BLE, "lock fail");

    Server *it = NULL;
    bool found = false;
    GeneralConnectionParam infoTemp = {0};
    LIST_FOR_EACH_ENTRY(it, &g_generalManager.servers->list, Server, node) {
        if (StrCmpIgnoreCase(it->info.name, info->name) == 0 &&
            StrCmpIgnoreCase(it->info.bundleName, info->bundleName) == 0) {
            found = true;
            break;
        }
    }

    if (!found) {
        (void)SoftBusMutexUnlock(&g_generalManager.servers->lock);
        return false;
    }

    if (strncpy_s(infoTemp.name, GENERAL_NAME_LEN, it->info.name, GENERAL_NAME_LEN - 1) != EOK ||
        strncpy_s(infoTemp.pkgName, PKG_NAME_SIZE_MAX, it->info.pkgName, PKG_NAME_SIZE_MAX - 1) != EOK ||
        strncpy_s(infoTemp.bundleName, BUNDLE_NAME_MAX, it->info.bundleName, BUNDLE_NAME_MAX - 1) != EOK) {
        CONN_LOGE(CONN_BLE, "copy info fail");
        (void)SoftBusMutexUnlock(&g_generalManager.servers->lock);
        return false;
    }
    infoTemp.pid = it->info.pid;
    (void)SoftBusMutexUnlock(&g_generalManager.servers->lock);

    ret = SoftBusMutexLock(&generalConnection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, false, CONN_BLE, "lock fail");
    if (strncpy_s(generalConnection->info.name, GENERAL_NAME_LEN, infoTemp.name, GENERAL_NAME_LEN - 1) != EOK ||
        strncpy_s(generalConnection->info.pkgName, PKG_NAME_SIZE_MAX,
            infoTemp.pkgName, PKG_NAME_SIZE_MAX - 1) != EOK ||
        strncpy_s(generalConnection->info.bundleName,
            BUNDLE_NAME_MAX, infoTemp.bundleName, BUNDLE_NAME_MAX - 1) != EOK) {
        CONN_LOGE(CONN_BLE, "copy fail");
        (void)SoftBusMutexUnlock(&generalConnection->lock);
        return false;
    }
    generalConnection->info.pid = infoTemp.pid;
    (void)SoftBusMutexUnlock(&generalConnection->lock);
    return true;
}

static void OnReuseConnectSucc(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info)
{
    (void)requestId;
    (void)connectionId;
    (void)info;
}

static void OnReuseConnectFail(uint32_t requestId, int32_t reason)
{
    (void)requestId;
    (void)reason;
}

static bool IsLocalStartMerge(struct GeneralConnection *generalConnection)
{
    int32_t ret = SoftBusMutexLock(&generalConnection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, false, CONN_BLE, "lock fail");
    bool isSupportNetWorkIdExchange = generalConnection->isSupportNetWorkIdExchange;
    (void)SoftBusMutexUnlock(&generalConnection->lock);

    char localUdid[UDID_BUF_LEN] = {0};
    char localNetworkId[NETWORK_ID_BUF_LEN] = {0};
    ret = isSupportNetWorkIdExchange ?
        LnnGetLocalStrInfo(STRING_KEY_NETWORKID, localNetworkId, NETWORK_ID_BUF_LEN) :
        LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, false,
        CONN_BLE, "get local str info fail, error=%{public}d", ret);
    return isSupportNetWorkIdExchange ? (strcmp(localNetworkId, generalConnection->networkId) > 0):
        (strcmp(localUdid, generalConnection->udid) > 0);
}

static void MergeConnectionInner(struct GeneralConnection *out,
    struct GeneralConnection *generalConnection)
{
    CONN_LOGI(CONN_BLE, "outgeneralId=%{public}u, generalId=%{public}u", out->generalId,
        generalConnection->generalId);
    CONN_CHECK_AND_RETURN_LOGE(IsLocalStartMerge(generalConnection), CONN_BLE, "wait peer start merge");
    // merge underlayer connection need reconnect it, and wait peer disconnect
    ConnectResult result = {
        .OnConnectSuccessed = OnReuseConnectSucc,
        .OnConnectFailed = OnReuseConnectFail,
    };
    (void)StartConnConnectDevice(generalConnection->addr, generalConnection->protocol, &result, 0);
    CONN_LOGI(CONN_BLE, "merge connection, before generalId=%{public}u", out->generalId);
    GeneralSendMergeMessage(out, generalConnection->peerGeneralId);
    int32_t ret = SoftBusMutexLock(&out->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_BLE, "lock fail");
    out->underlayerHandle = generalConnection->underlayerHandle;
    (void)SoftBusMutexUnlock(&out->lock);
}

static void DisconnectDelay(uint32_t connectionId)
{
    ConnDisconnectDevice(connectionId);
}

static bool IsSameDevice(struct GeneralConnection *generalConnectionLf, struct GeneralConnection *generalConnectionRf)
{
    bool isSupportNetWorkIdExchange = generalConnectionLf->isSupportNetWorkIdExchange;
    return isSupportNetWorkIdExchange ?
        (StrCmpIgnoreCase(generalConnectionLf->networkId, generalConnectionRf->networkId) == 0):
        (StrCmpIgnoreCase(generalConnectionLf->udid, generalConnectionRf->udid) == 0);
}

static void MergeConnection(uint32_t generalId)
{
    struct GeneralConnection *generalConnection = GetConnectionByGeneralId(generalId);
    CONN_CHECK_AND_RETURN_LOGE(generalConnection != NULL, CONN_BLE, "connection is null");

    if (SoftBusMutexLock(&g_generalManager.connections->lock) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "try to get connection lock fail");
        ConnReturnGeneralConnection(&generalConnection);
        return;
    }
    struct GeneralConnection *it = NULL;
    struct GeneralConnection *out = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_generalManager.connections->list, struct GeneralConnection, node) {
        if (IsSameDevice(generalConnection, it) && it->underlayerHandle != generalConnection->underlayerHandle) {
            out = it;
            out->reference(out);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);
    if (out != NULL && out->state == STATE_CONNECTED) {
        MergeConnectionInner(out, generalConnection);
    }
    if (out != NULL) {
        out->dereference(out);
    }
    ConnReturnGeneralConnection(&generalConnection);
}

static void OnConnectTimeout(uint32_t generalId)
{
    struct GeneralConnection *generalConnection = GetConnectionByGeneralId(generalId);
    CONN_CHECK_AND_RETURN_LOGE(generalConnection != NULL, CONN_BLE,
        "connection is null, generalId=%{public}u", generalId);
    g_generalConnectionListener.onConnectFailed(&generalConnection->info,
        generalConnection->generalId, SOFTBUS_CONN_GENERAL_CONNECT_TIMEOUT);
    GeneralSendResetMessage(generalConnection);
    ConnRemoveGeneralConnection(generalConnection);
    ConnReturnGeneralConnection(&generalConnection);
}

static void ConnFreeGeneralConnection(struct GeneralConnection *generalConnection)
{
    SoftBusMutexDestroy(&generalConnection->lock);
    SoftBusFree(generalConnection);
}

static void Reference(struct GeneralConnection *target)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&target->lock) == SOFTBUS_OK, CONN_BLE,
        "lock fail");
    target->objectRc += 1;
    (void)SoftBusMutexUnlock(&target->lock);
}

static void Dereference(struct GeneralConnection *underlayer)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&underlayer->lock) == SOFTBUS_OK, CONN_BLE,
        "lock fail");
    underlayer->objectRc -= 1;
    int32_t objectRc = underlayer->objectRc;
    (void)SoftBusMutexUnlock(&underlayer->lock);
    if (objectRc <= 0) {
        CONN_LOGI(CONN_BLE, "release connection, generalId=%{public}u", underlayer->generalId);
        ConnFreeGeneralConnection(underlayer);
    }
}

static bool IsAllowSave(const char *bundleName, bool isFindServer)
{
    int32_t count = 0;
    if (!isFindServer) {
        CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_generalManager.connections->lock) == SOFTBUS_OK,
            false, CONN_BLE, "lock fail");
        struct GeneralConnection *it = NULL;
        LIST_FOR_EACH_ENTRY(it, &g_generalManager.connections->list, struct GeneralConnection, node) {
            if (StrCmpIgnoreCase(it->info.bundleName, bundleName) == 0 && it->isClient) {
                count += 1;
            }
        }
        (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);
    } else {
        CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_generalManager.servers->lock) == SOFTBUS_OK,
            false, CONN_BLE, "lock fail");
        Server *item = NULL;
        LIST_FOR_EACH_ENTRY(item, &g_generalManager.servers->list, Server, node) {
            if (StrCmpIgnoreCase(item->info.bundleName, bundleName) == 0) {
                count += 1;
            }
        }
        (void)SoftBusMutexUnlock(&g_generalManager.servers->lock);
    }
    if (count >= GENERAL_PKGNAME_MAX_COUNT) {
        CONN_LOGE(CONN_BLE, "create pkgName is max, not allowed");
        return false;
    }
    return true;
}

static struct GeneralConnection *CreateConnection(const GeneralConnectionParam *param, const char *addr,
    uint32_t underlayerHandle, bool isClient, int32_t *errorCode)
{
    if (!IsAllowSave(param->bundleName, false)) {
        CONN_LOGE(CONN_BLE, "add pkg name is max");
        *errorCode = SOFTBUS_CONN_GENERAL_CREATE_CLIENT_MAX;
        return NULL;
    }

    struct GeneralConnection *connection = (struct GeneralConnection *)SoftBusCalloc(sizeof(struct GeneralConnection));
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, NULL, CONN_BLE, "calloc connection fail");
    ListInit(&connection->node);
    connection->underlayerHandle = underlayerHandle;
    if (strncpy_s(connection->addr, BT_MAC_LEN, addr, BT_MAC_LEN - 1) != EOK ||
        strncpy_s(connection->info.name, GENERAL_NAME_LEN, param->name, GENERAL_NAME_LEN - 1) != EOK ||
        strncpy_s(connection->info.pkgName, PKG_NAME_SIZE_MAX, param->pkgName, PKG_NAME_SIZE_MAX - 1) != EOK ||
        strncpy_s(connection->info.bundleName, BUNDLE_NAME_MAX, param->bundleName, BUNDLE_NAME_MAX - 1) != EOK) {
        CONN_LOGE(CONN_BLE, "copy fail");
        SoftBusFree(connection);
        *errorCode = SOFTBUS_STRCPY_ERR;
        return NULL;
    }
    connection->reference = Reference;
    connection->dereference = Dereference;
    connection->info.pid = param->pid;
    if (SoftBusMutexInit(&connection->lock, NULL) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "init lock fail");
        SoftBusFree(connection);
        *errorCode = SOFTBUS_LOCK_ERR;
        return NULL;
    }
    connection->protocol = BLE_COC;
    connection->objectRc = 1;
    connection->isClient = isClient;
    connection->requestId = GenerateRequestId();
    connection->state = STATE_CONNECTING;
    connection->abilityBitSet = 1 << GENERAL_FEATURE_SUPPORT_COC;
    return connection;
}

static int32_t SaveConnection(struct GeneralConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(
        connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "invalid param, connection is null");
    int32_t ret = SoftBusMutexLock(&g_generalManager.connections->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_BLE, "invalid param, connection is null");
    uint32_t generalId = 0;
    do {
        generalId = AllocateGeneralIdUnsafe();
    } while (generalId == 0);
    connection->generalId = generalId;
    connection->reference(connection);
    ListAdd(&g_generalManager.connections->list, &connection->node);
    (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);
    return SOFTBUS_OK;
}

static void UpdatePeerGeneralId(struct GeneralConnection *connection, GeneralConnectionInfo *info)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK, CONN_BLE,
        "lock fail");
    connection->peerGeneralId = info->peerId;
    (void)SoftBusMutexUnlock(&connection->lock);
}

static int32_t ProcessHandshakeMessage(uint32_t connectionId, GeneralConnectionInfo *info)
{
    GeneralConnectionParam param = {0};
    int32_t ret = SOFTBUS_OK;
    char addr[BT_MAC_LEN] = {0};
    struct GeneralConnection *generalConnection = CreateConnection(&param, addr, connectionId, false, &ret);
    CONN_CHECK_AND_RETURN_RET_LOGE(generalConnection != NULL, ret, CONN_BLE,
        "create connection fail");
    ret = SaveConnection(generalConnection);
    if (ret != SOFTBUS_OK) {
        generalConnection->dereference(generalConnection);
        return ret;
    }
    UpdatePeerGeneralId(generalConnection, info);
    CONN_LOGI(CONN_BLE, "process handshake message, peer generalId=%{public}u, local generalId=%{public}u",
        generalConnection->peerGeneralId, generalConnection->generalId);
    ret = SetConnectionDeviceId(generalConnection);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "set param fail, error=%{public}d", ret);
        ConnRemoveGeneralConnection(generalConnection);
        generalConnection->dereference(generalConnection);
        return ret;
    }
    bool exit = FindInfoFromServer(info, generalConnection);
    int32_t status = SOFTBUS_OK;
    if (!exit) {
        status = SOFTBUS_CONN_GENERAL_SERVER_NOT_OPENED;
    }
    ret = GeneralSessionNegotiation(generalConnection, status, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK);
    if (ret != SOFTBUS_OK || status != SOFTBUS_OK) {
        GeneralSendResetMessage(generalConnection);
        ConnRemoveGeneralConnection(generalConnection);
        generalConnection->dereference(generalConnection);
        return ret;
    }
    UpdateConnectionState(generalConnection, STATE_CONNECTING, STATE_CONNECTED);
    CONN_LOGI(CONN_BLE, "server accept, generalId=%{public}u", generalConnection->generalId);
    g_generalConnectionListener.onAcceptConnect(&generalConnection->info, generalConnection->generalId);
    uint32_t generalId = generalConnection->generalId;
    generalConnection->dereference(generalConnection);
    CONN_CHECK_AND_RETURN_RET_LOGE(ConnPostMsgToLooper(&g_generalManagerSyncHandler, GENERAL_MGR_MSG_MERGE_CMD,
        generalId, 0, NULL, 0) == SOFTBUS_OK, ret, CONN_BLE,
        "post merge msg fail");
    return ret;
}

static void NotifyConnectFailed(struct GeneralConnection *generalConnection, int32_t reason)
{
    if (generalConnection->state == STATE_CONNECTED) {
        g_generalConnectionListener.onConnectionDisconnected(&generalConnection->info,
            generalConnection->generalId, reason);
        return;
    }
    if (generalConnection->isClient) {
        g_generalConnectionListener.onConnectFailed(&generalConnection->info,
            generalConnection->generalId, reason);
    }
}

static struct GeneralConnection *GetValidConnectionByGeneralId(uint32_t underlayerHandle, uint32_t generalId)
{
    struct GeneralConnection *generalConnection = GetConnectionByGeneralId(generalId);
    CONN_CHECK_AND_RETURN_RET_LOGE(generalConnection != NULL, NULL, CONN_BLE,
        "connection is null, generalId=%{public}u", generalId);
    if (generalConnection->underlayerHandle != underlayerHandle) {
        CONN_LOGE(CONN_BLE, "unexpect message, recvId=%{public}u, localId=%{public}u",
            underlayerHandle, generalConnection->underlayerHandle);
        ConnReturnGeneralConnection(&generalConnection);
        return NULL;
    }
    return generalConnection;
}

static int32_t ProcessMergeMessage(uint32_t connectionId, GeneralConnectionInfo *info)
{
    struct GeneralConnection *generalConnection = GetValidConnectionByGeneralId(connectionId, info->localId);
    CONN_CHECK_AND_RETURN_RET_LOGE(generalConnection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "connection is null, generalId=%{public}u", info->localId);
    ConnDisconnectDevice(connectionId);
    struct GeneralConnection *mergedConnection = GetConnectionByGeneralId(info->updateHandle);
    if (mergedConnection == NULL) {
        CONN_LOGE(CONN_BLE, "can not get connection, generalId=%{public}u", info->updateHandle);
        ConnReturnGeneralConnection(&generalConnection);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t mergedHandle = mergedConnection->underlayerHandle;
    ConnReturnGeneralConnection(&mergedConnection);
    int32_t ret = SoftBusMutexLock(&generalConnection->lock);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "locak fail, generalId=%{public}u, err=%{public}d",
            generalConnection->generalId, ret);
        ConnReturnGeneralConnection(&generalConnection);
        return SOFTBUS_LOCK_ERR;
    }
    CONN_LOGI(CONN_BLE, "recv merge msg, generalId=%{public}u, before handle =%{public}u, update handle =%{public}u",
        generalConnection->generalId, generalConnection->underlayerHandle, mergedHandle);
    generalConnection->underlayerHandle = mergedHandle;
    (void)SoftBusMutexUnlock(&generalConnection->lock);
    ConnReturnGeneralConnection(&generalConnection);
    return SOFTBUS_OK;
}

static int32_t ProcessResetMessage(uint32_t connectionId, GeneralConnectionInfo *info)
{
    struct GeneralConnection *generalConnection = GetValidConnectionByGeneralId(connectionId, info->localId);
    CONN_CHECK_AND_RETURN_RET_LOGE(generalConnection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "connection is null, generalId=%{public}u", info->localId);
    CONN_LOGI(CONN_BLE, "recv reset msg, generalId=%{public}u", generalConnection->generalId);
    ConnRemoveMsgFromLooper(&g_generalManagerSyncHandler, GENERAL_MGR_MSG_CONNECT_TIMEOUT,
        generalConnection->generalId, 0, NULL);

    NotifyConnectFailed(generalConnection, SOFTBUS_CONN_GENERAL_PEER_CONNECTION_CLOSE);
    if (generalConnection->isClient) {
        ConnDisconnectDevice(generalConnection->underlayerHandle);
    }
    ConnRemoveGeneralConnection(generalConnection);
    ConnReturnGeneralConnection(&generalConnection);
    return SOFTBUS_OK;
}

static void UpdateGeneralConnectionByInfo(struct GeneralConnection *generalConnection, GeneralConnectionInfo *info)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&generalConnection->lock) == SOFTBUS_OK, CONN_BLE,
        "lock fail");
    generalConnection->abilityBitSet = info->abilityBitSet;
    generalConnection->peerGeneralId = info->peerId;
    (void)SoftBusMutexUnlock(&generalConnection->lock);
}

static int32_t ProcessHandShakeAck(uint32_t connectionId, GeneralConnectionInfo *info)
{
    struct GeneralConnection *generalConnection = GetValidConnectionByGeneralId(connectionId, info->localId);
    CONN_CHECK_AND_RETURN_RET_LOGE(generalConnection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "connection is null, generalId=%{public}u", info->peerId);
    ConnRemoveMsgFromLooper(&g_generalManagerSyncHandler, GENERAL_MGR_MSG_CONNECT_TIMEOUT,
        generalConnection->generalId, 0, NULL);
    if (info->ackStatus != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "hand shake fail, ackStatus=%{public}d, generalId=%{public}u",
            info->ackStatus, generalConnection->generalId);
        g_generalConnectionListener.onConnectFailed(&generalConnection->info,
            generalConnection->generalId, info->ackStatus);
        ConnReturnGeneralConnection(&generalConnection);
        return info->ackStatus;
    }
    UpdateGeneralConnectionByInfo(generalConnection, info);
    UpdateConnectionState(generalConnection, STATE_CONNECTING, STATE_CONNECTED);
    CONN_LOGI(CONN_BLE, "recv handshake ack, ackStatus=%{public}d, report connect success, generalId=%{public}u",
        info->ackStatus, generalConnection->generalId);
    g_generalConnectionListener.onConnectSuccess(&generalConnection->info, generalConnection->generalId);
    if (ConnPostMsgToLooper(&g_generalManagerSyncHandler, GENERAL_MGR_MSG_MERGE_CMD,
        generalConnection->generalId, 0, NULL, 0) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "post merage msg fail");
    }
    ConnReturnGeneralConnection(&generalConnection);
    return SOFTBUS_OK;
}

static int32_t ProcessInnerMessageByType(
    uint32_t connectionId, GeneralConnectionMsgType msgType, GeneralConnectionInfo *info)
{
    switch (msgType) {
        case GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE:
            return ProcessHandshakeMessage(connectionId, info);
        case GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK:
            return ProcessHandShakeAck(connectionId, info);
        case GENERAL_CONNECTION_MSG_TYPE_MERGE:
            return ProcessMergeMessage(connectionId, info);
        case GENERAL_CONNECTION_MSG_TYPE_RESET:
            return ProcessResetMessage(connectionId, info);
        default:
            return SOFTBUS_CONN_GENERAL_MSG_NOT_FOUND;
    }
    return SOFTBUS_OK;
}

static void OnCommConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

static void OnCommDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    CONN_CHECK_AND_RETURN_LOGE(info != NULL, CONN_BLE, "info is null");
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_generalManager.connections->lock) == SOFTBUS_OK, CONN_BLE,
        "lock fail");
    CONN_LOGI(CONN_BLE, "on connect disconnected, connId=%{public}u", connectionId);
    struct GeneralConnection *it = NULL;
    struct GeneralConnection *next = NULL;
    ListNode waitNotify = {0};
    ListInit(&waitNotify);
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_generalManager.connections->list,
        struct GeneralConnection, node) {
        if (it->underlayerHandle == connectionId) {
            CONN_LOGI(CONN_BLE, "remove connection, generalId=%{public}u", it->generalId);
            ListDelete(&it->node);
            ListAdd(&waitNotify, &it->node);
        }
    }
    (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);

    struct GeneralConnection *item = NULL;
    struct GeneralConnection *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &waitNotify, struct GeneralConnection, node) {
        ListDelete(&item->node);
        NotifyConnectFailed(item, SOFTBUS_CONN_GENERAL_CONNECTION_CLOSE);
        ConnReturnGeneralConnection(&item);
    }
}

static void OnCommDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    if (data == NULL || len < (int32_t)GENERAL_CONNECTION_HEADER_SIZE || moduleId != MODULE_BLE_GENERAL) {
        CONN_LOGE(CONN_BLE, "invalid param, connId=%{public}u", connectionId);
        return;
    }
    GeneralConnectionHead head = *(GeneralConnectionHead *)data;
    UnpackGeneralHead(&head);
    GeneralConnectionMsgType msgType = (GeneralConnectionMsgType)head.msgType;
    if (msgType >= GENERAL_CONNECTION_MSG_TYPE_MAX || (uint32_t)len < head.headLen) {
        CONN_LOGE(CONN_BLE, "invalid msgType, msgType=%{public}u, len=%{public}d, headLen=%{public}u",
            msgType, len, head.headLen);
        return;
    }
    GeneralConnectionInfo info =  { { 0 } };
    info.peerId = head.localId;
    info.localId = head.peerId;
    uint32_t recvDataLen = (uint32_t)len - head.headLen; // len greater than GENERAL_CONNECTION_HEADER_SIZE
    uint8_t *recvData = (uint8_t *)data + head.headLen;
    CONN_LOGI(CONN_BLE, "handle=%{public}u,"
        "recv data len=%{public}d, seq=%{public}" PRId64 ", msgtype=%{public}u", info.localId, len, seq, msgType);
    if (msgType == GENERAL_CONNECTION_MSG_TYPE_NORMAL) {
        struct GeneralConnection *connection = GetValidConnectionByGeneralId(connectionId, head.peerId);
        CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_BLE, "conncetion is null");
        CONN_LOGI(CONN_BLE, "recv data generalId=%{public}u, len=%{public}d",
            connection->generalId, recvDataLen);
        g_generalConnectionListener.onDataReceived(&connection->info,
            connection->generalId, recvData, recvDataLen);
        ConnReturnGeneralConnection(&connection);
        return;
    }
    int32_t ret = GeneralConnectionUnpackMsg(recvData, recvDataLen, &info, msgType);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_BLE, "unpack msg fail, handle=%{public}u, error=%{public}d",
        info.localId, ret);
    ret = ProcessInnerMessageByType(connectionId, msgType, &info);
    CONN_LOGD(CONN_BLE, "process inner msg, handle=%{public}u, ret=%{public}d", info.localId, ret);
}

static int32_t RegisterListener(const GeneralConnectionListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(listener != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "listener is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onConnectFailed != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "listener onConnectFailed is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onDataReceived != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "listener onDataReceived is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onAcceptConnect != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "listener onAcceptConnect is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onConnectSuccess != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "listener onConnectSuccess is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onConnectionDisconnected != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "listener onConnectionDisconnected is null");
    g_generalConnectionListener = *listener;
    return SOFTBUS_OK;
}

static int32_t Connect(const GeneralConnectionParam *param, const char *addr)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "param is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(addr != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "addr is null");
    ConnectResult result = {
        .OnConnectSuccessed = OnCommConnectSucc,
        .OnConnectFailed = OnCommConnectFail,
    };
    int32_t status = SOFTBUS_OK;
    struct GeneralConnection *generalConnection = CreateConnection(param, addr, 0, true, &status);
    CONN_CHECK_AND_RETURN_RET_LOGE(generalConnection != NULL, status, CONN_BLE,
        "create connection fail");
    status = SaveConnection(generalConnection);
    if (status != SOFTBUS_OK) {
        generalConnection->dereference(generalConnection);
        return status;
    }
    status= StartConnConnectDevice(generalConnection->addr, BLE_COC, &result, generalConnection->requestId);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "connect fail, err=%{public}d", status);
        ConnRemoveGeneralConnection(generalConnection);
        generalConnection->dereference(generalConnection);
        return SOFTBUS_CONN_GENERAL_CONNECT_FAILED;
    }
    status = ConnPostMsgToLooper(&g_generalManagerSyncHandler, GENERAL_MGR_MSG_CONNECT_TIMEOUT,
        generalConnection->generalId, 0, NULL, GENERAL_CONNECT_TIMEOUT_MILLIS);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "post timeout msg fail, err=%{public}d", status);
        ConnRemoveGeneralConnection(generalConnection);
        generalConnection->dereference(generalConnection);
        return status;
    }
    CONN_LOGI(CONN_BLE, "recv connect request, handle=%{public}u, reqId=%{public}u",
        generalConnection->generalId, generalConnection->requestId);
    uint32_t handle = generalConnection->generalId;
    generalConnection->dereference(generalConnection);
    return handle;
}

static struct GeneralConnection *GetConnectionByGeneralIdAndCheckPid(uint32_t generalHandle, int32_t pid)
{
    struct GeneralConnection *generalConnection = GetConnectionByGeneralId(generalHandle);
    CONN_CHECK_AND_RETURN_RET_LOGE(generalConnection != NULL, NULL, CONN_BLE,
        "connection is null, generalId=%{public}u", generalHandle);
    if (generalConnection->info.pid != pid) {
        CONN_LOGE(CONN_BLE, "invalid pid=%{public}d, generalId=%{public}u, localPid=%{public}d",
            pid, generalHandle, generalConnection->info.pid);
        ConnReturnGeneralConnection(&generalConnection);
        return NULL;
    }
    return generalConnection;
}

static int32_t Send(uint32_t generalHandle, const uint8_t *data, uint32_t dataLen, int32_t pid)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "data is null");
    struct GeneralConnection *generalConnection = GetConnectionByGeneralIdAndCheckPid(generalHandle, pid);
    CONN_CHECK_AND_RETURN_RET_LOGE(generalConnection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "invalid param, generalId=%{public}u", generalHandle);
    int32_t ret = SoftBusMutexLock(&generalConnection->lock);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "lock fail, handle=%{public}u, err=%{public}u",
            generalConnection->generalId, ret);
        ConnReturnGeneralConnection(&generalConnection);
        return SOFTBUS_LOCK_ERR;
    }
    if (generalConnection->state != STATE_CONNECTED) {
        CONN_LOGE(CONN_BLE, "connection not ready, handle=%{public}u", generalConnection->generalId);
        (void)SoftBusMutexUnlock(&generalConnection->lock);
        ConnReturnGeneralConnection(&generalConnection);
        return SOFTBUS_CONN_GENERAL_CONNECTION_NOT_READY;
    }
    uint32_t underlayerHandle = generalConnection->underlayerHandle;
    (void)SoftBusMutexUnlock(&generalConnection->lock);

    OutData *outData = PackData(generalConnection, data, dataLen);
    ConnReturnGeneralConnection(&generalConnection);
    CONN_CHECK_AND_RETURN_RET_LOGE(outData != NULL, SOFTBUS_MALLOC_ERR, CONN_BLE,
        "outdata is null, generalId=%{public}u", generalHandle);
    CONN_LOGI(CONN_BLE, "send data, handle=%{public}u, len=%{public}u", generalHandle, dataLen);
    ret = SendInner(outData, underlayerHandle, MODULE_BLE_GENERAL, pid);
    FreeOutData(outData);
    return ret;
}

static void Disconnect(uint32_t generalHandle, int32_t pid)
{
    struct GeneralConnection *generalConnection = GetConnectionByGeneralIdAndCheckPid(generalHandle, pid);
    CONN_CHECK_AND_RETURN_LOGE(generalConnection != NULL, CONN_BLE,
        "invalid param, generalId=%{public}u", generalHandle);
    CONN_LOGI(CONN_BLE, "disconnect connection, generalId=%{public}u, connId=%{public}u",
        generalHandle, generalConnection->underlayerHandle);
    GeneralSendResetMessage(generalConnection);
    ConnRemoveGeneralConnection(generalConnection);
    ConnReturnGeneralConnection(&generalConnection);
    return;
}

static int32_t GetPeerDeviceId(uint32_t generalHandle, char *addr, uint32_t length, uint32_t tokenId, int32_t pid)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(addr != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "addr is null, get deviceId fail");
    CONN_CHECK_AND_RETURN_RET_LOGE(length == BT_MAC_LEN, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "invalid param, generalId=%{public}u, len=%{public}u", generalHandle, length);

    struct GeneralConnection *generalConnection = GetConnectionByGeneralIdAndCheckPid(generalHandle, pid);
    CONN_CHECK_AND_RETURN_RET_LOGE(generalConnection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "invalid param, generalId=%{public}u", generalHandle);
    int32_t ret = SoftBusGetRandomAddress(generalConnection->addr, addr, (int32_t)tokenId);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "get mac fail, generalId=%{public}u", generalHandle);
    }
    ConnReturnGeneralConnection(&generalConnection);
    return ret;
}

static int32_t CreateServer(const GeneralConnectionParam *param)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "create server fail, param is null");
    if (!IsAllowSave(param->bundleName, true)) {
        CONN_LOGE(CONN_BLE, "add pkg name is max");
        return SOFTBUS_CONN_GENERAL_CREATE_SERVER_MAX;
    }
    int32_t ret = SoftBusMutexLock(&g_generalManager.servers->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        CONN_BLE, "lock servers fail");
    Server *it = NULL;
    bool exit = false;
    LIST_FOR_EACH_ENTRY(it, &g_generalManager.servers->list, Server, node) {
        if (StrCmpIgnoreCase(it->info.name, param->name) == 0 &&
            StrCmpIgnoreCase(it->info.bundleName, param->bundleName) == 0) {
            exit = true;
            break;
        }
    }
    if (exit) {
        CONN_LOGE(CONN_BLE, "server name already exit, not allowed");
        (void)SoftBusMutexUnlock(&g_generalManager.servers->lock);
        return SOFTBUS_CONN_GENERAL_DUPLICATE_SERVER;
    }
    Server *serverNode = NewServerNode(param);
    if (serverNode == NULL) {
        CONN_LOGE(CONN_BLE, "new server is null");
        (void)SoftBusMutexUnlock(&g_generalManager.servers->lock);
        return SOFTBUS_MALLOC_ERR;
    }
    ListAdd(&g_generalManager.servers->list, &serverNode->node);
    (void)SoftBusMutexUnlock(&g_generalManager.servers->lock);
    return SOFTBUS_OK;
}

static void CloseServer(const GeneralConnectionParam *param)
{
    CONN_CHECK_AND_RETURN_LOGE(param != NULL, CONN_BLE, "close server fail, param is null");
    int32_t ret = SoftBusMutexLock(&g_generalManager.servers->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_BLE, "lock names fail");
    Server *it = NULL;
    Server *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_generalManager.servers->list, Server, node) {
        if (StrCmpIgnoreCase(it->info.name, param->name) == 0 &&
            StrCmpIgnoreCase(it->info.bundleName, param->bundleName) == 0) {
            ListDelete(&it->node);
            FreeServerNode(&it);
        }
    }
    (void)SoftBusMutexUnlock(&g_generalManager.servers->lock);
    return;
}

static GeneralConnectionManager g_manager = {
    .registerListener = RegisterListener,
    .createServer = CreateServer,
    .closeServer = CloseServer,
    .connect = Connect,
    .send = Send,
    .disconnect = Disconnect,
    .getPeerDeviceId = GetPeerDeviceId,
    .cleanupGeneralConnection = ClearAllGeneralConnection,
};

GeneralConnectionManager *GetGeneralConnectionManager(void)
{
    return &g_manager;
}

int32_t InitGeneralConnectionManager(void)
{
    ConnectCallback connCb = {
        .OnConnected = OnCommConnected,
        .OnDisconnected = OnCommDisconnected,
        .OnDataReceived = OnCommDataReceived,
    };
    int32_t ret = SoftBusMutexInit(&g_requestIdLock, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_INIT, "init lock fail");
    ret = ConnSetConnectCallback(MODULE_BLE_GENERAL, &connCb);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "set callback fail");
        SoftBusMutexDestroy(&g_requestIdLock);
        return ret;
    }
    SoftBusList *connections = CreateSoftBusList();
    if (connections == NULL) {
        CONN_LOGE(CONN_INIT, "create connections list fail");
        SoftBusMutexDestroy(&g_requestIdLock);
        return SOFTBUS_CREATE_LIST_ERR;
    }
    g_generalManager.connections = connections;
    SoftBusList *servers = CreateSoftBusList();
    if (servers == NULL) {
        CONN_LOGE(CONN_INIT, "create servers list fail");
        SoftBusMutexDestroy(&g_requestIdLock);
        DestroySoftBusList(g_generalManager.connections);
        return SOFTBUS_CREATE_LIST_ERR;
    }
    g_generalManager.servers = servers;
    g_generalManagerSyncHandler.handler.looper = GetLooper(LOOP_TYPE_CONN);
    if (g_generalManagerSyncHandler.handler.looper == NULL) {
        CONN_LOGE(CONN_INIT, "create names list fail");
        SoftBusMutexDestroy(&g_requestIdLock);
        DestroySoftBusList(g_generalManager.connections);
        DestroySoftBusList(g_generalManager.servers);
        return SOFTBUS_LOOPER_ERR;
    }
    CONN_LOGI(CONN_INIT, "init success");
    return SOFTBUS_OK;
}