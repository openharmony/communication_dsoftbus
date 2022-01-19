/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: br connection mannager module.
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

#include "br_connection_manager.h"

#include "common_list.h"
#include "message_handler.h"

#ifdef __LITEOS_M__
#include "ohos_types.h"
#endif

#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"
#include "stdbool.h"
#include "string.h"
#include "time.h"
#include "unistd.h"
#include "wrapper_br_interface.h"

static pthread_mutex_t g_connectionLock;
static LIST_HEAD(g_connection_list);
static int32_t g_brBuffSize;
static int16_t g_nextConnectionId = 0;

void InitBrConnectionManager(int32_t brBuffSize)
{
    g_brBuffSize = brBuffSize + sizeof(ConnPktHead);
    pthread_mutex_init(&g_connectionLock, NULL);
}

bool IsExitConnectionById(uint32_t connId)
{
    (void)pthread_mutex_lock(&g_connectionLock);
    ListNode *item = NULL;
    BrConnectionInfo *itemNode = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->connectionId != connId) {
            continue;
        }
        (void)pthread_mutex_unlock(&g_connectionLock);
        return true;
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return false;
}

bool IsExitBrConnectByFd(int32_t socketFd)
{
    (void)pthread_mutex_lock(&g_connectionLock);
    ListNode *item = NULL;
    BrConnectionInfo *itemNode = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (socketFd == itemNode->socketFd) {
            (void)pthread_mutex_unlock(&g_connectionLock);
            return true;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return false;
}

BrConnectionInfo *GetConnectionRef(uint32_t connId)
{
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[GetConnectionRef] mutex failed");
        return NULL;
    }
    ListNode *item = NULL;
    BrConnectionInfo *itemNode = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->connectionId == connId) {
            itemNode->infoObjRefCount++;
            (void)pthread_mutex_unlock(&g_connectionLock);
            return itemNode;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return NULL;
}

void ReleaseBrconnectionNode(BrConnectionInfo *conn)
{
    if (conn == NULL) {
        return;
    }
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    RequestInfo *requestInfo = NULL;
    LIST_FOR_EACH_SAFE(item, nextItem, &conn->requestList) {
        requestInfo = LIST_ENTRY(item, RequestInfo, node);
        ListDelete(&requestInfo->node);
        SoftBusFree(requestInfo);
    }
    pthread_cond_destroy(&conn->congestCond);
    pthread_mutex_destroy(&conn->lock);
    SoftBusFree(conn->recvBuf);
    SoftBusFree(conn);
}

void ReleaseConnectionRef(BrConnectionInfo *connInfo)
{
    if (connInfo == NULL) {
        return;
    }
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ReleaseConnectionRef] lock mutex failed");
        return;
    }
    connInfo->infoObjRefCount--;
    if (connInfo->infoObjRefCount <= 0) {
        ListDelete(&connInfo->node);
        ReleaseBrconnectionNode(connInfo);
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
}

void ReleaseConnectionRefByConnId(uint32_t connId)
{
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ReleaseConnectionRef] lock mutex failed");
        return;
    }
    ListNode *item = NULL;
    BrConnectionInfo *connInfo = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->connectionId == connId) {
            connInfo = itemNode;
            break;
        }
    }
    if (connInfo != NULL) {
        connInfo->infoObjRefCount--;
        if (connInfo->infoObjRefCount <= 0) {
            ListDelete(&connInfo->node);
            ReleaseBrconnectionNode(connInfo);
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
}

static uint32_t AllocNewConnectionIdLocked(void)
{
    uint32_t tempId;
    while (1) {
        g_nextConnectionId++;
        tempId = (CONNECT_BR << CONNECT_TYPE_SHIFT) + g_nextConnectionId;
        if (!IsExitConnectionById(tempId)) {
            break;
        }
    }
    return tempId;
}

BrConnectionInfo* CreateBrconnectionNode(bool clientFlag)
{
    BrConnectionInfo *newConnInfo = (BrConnectionInfo *)SoftBusCalloc(sizeof(BrConnectionInfo));
    if (newConnInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[Create BrConnInfo malloc fail.]");
        return NULL;
    }
    newConnInfo->recvBuf = (char *)SoftBusCalloc(g_brBuffSize);
    newConnInfo->recvSize = g_brBuffSize;
    if (newConnInfo->recvBuf == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[Create BrConnInfo malloc recvBuf fail]");
        SoftBusFree(newConnInfo);
        return NULL;
    }
    ListInit(&newConnInfo->node);
    ListInit(&newConnInfo->requestList);
    pthread_mutex_init(&newConnInfo->lock, NULL);
    newConnInfo->connectionId = AllocNewConnectionIdLocked();
    newConnInfo->recvPos = 0;
    newConnInfo->conGestState = BT_RFCOM_CONGEST_OFF;
    pthread_cond_init(&newConnInfo->congestCond, NULL);
    newConnInfo->refCount = 1;
    newConnInfo->infoObjRefCount = 1;
    newConnInfo->state = BR_CONNECTION_STATE_CONNECTING;
    newConnInfo->sideType = clientFlag ? BR_CLIENT_TYPE : BR_SERVICE_TYPE;
    return newConnInfo;
}

int32_t GetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    int32_t result = SOFTBUS_ERR;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->connectionId == connectionId) {
            info->isAvailable = 1;
            info->isServer = itemNode->sideType;
            info->type = CONNECT_BR;
            if (strcpy_s(info->info.brInfo.brMac, BT_MAC_LEN, itemNode->mac) != EOK) {
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

int32_t SetRefCountByConnId(int32_t delta, int32_t *refCount, uint32_t connectionId)
{
    int32_t state = BR_CONNECTION_STATE_CLOSED;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return state;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->connectionId == connectionId) {
            itemNode->refCount += delta;
            (*refCount) = itemNode->refCount;
            state = itemNode->state;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return state;
}

static void FreeCongestEvent(BrConnectionInfo *itemNode)
{
    itemNode->conGestState = BT_RFCOM_CONGEST_OFF;
    if (pthread_mutex_lock(&itemNode->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[FreeCongestEvent] mutex failed");
        return;
    }
    pthread_cond_broadcast(&itemNode->congestCond);
    (void)pthread_mutex_unlock(&itemNode->lock);
}

void SetBrConnStateByConnId(uint32_t connId, int32_t state)
{
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SetBrConnStateByConnId lock mutex failed");
        return;
    }
    ListNode *britem = NULL;
    BrConnectionInfo *itemNode = NULL;
    LIST_FOR_EACH(britem, &g_connection_list) {
        itemNode = LIST_ENTRY(britem, BrConnectionInfo, node);
        if (itemNode->connectionId == connId) {
            itemNode->state = state;
            if (state == BR_CONNECTION_STATE_CLOSED) {
                FreeCongestEvent(itemNode);
            }
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
}

uint32_t SetBrConnStateBySocket(int32_t socket, int32_t state, int32_t *perState)
{
    uint32_t connId = 0;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SetBrConnStateByConnId lock mutex failed");
        return connId;
    }
    ListNode *britem = NULL;
    BrConnectionInfo *itemNode = NULL;
    LIST_FOR_EACH(britem, &g_connection_list) {
        itemNode = LIST_ENTRY(britem, BrConnectionInfo, node);
        if (itemNode->socketFd == socket) {
            if (perState != NULL) {
                (*perState) = itemNode->state;
            }
            itemNode->state = state;
            if (state == BR_CONNECTION_STATE_CLOSED) {
                FreeCongestEvent(itemNode);
            }
            connId = itemNode->connectionId;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return connId;
}

int32_t AddRequestByConnId(uint32_t connId, RequestInfo *requestInfo)
{
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->connectionId == connId) {
            ListAdd(&itemNode->requestList, &requestInfo->node);
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return SOFTBUS_OK;
}

int32_t AddConnectionList(BrConnectionInfo *newConnInfo)
{
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    ListAdd(&g_connection_list, &newConnInfo->node);
    (void)pthread_mutex_unlock(&g_connectionLock);
    return SOFTBUS_OK;
}

void RfcomCongestEvent(int32_t socketFd, int32_t value)
{
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[RfcomCongestEvent] lock mutex failed");
        return;
    }
    ListNode *item = NULL;
    BrConnectionInfo *itemNode = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->socketFd == socketFd) {
            itemNode->conGestState = value;
            if (value == BT_RFCOM_CONGEST_OFF) {
                if (pthread_mutex_lock(&itemNode->lock) != 0) {
                    (void)pthread_mutex_unlock(&g_connectionLock);
                    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "CongestEvent lock itemNode failed");
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

static int32_t InitConnectionInfo(ConnectionInfo *connectionInfo, const BrConnectionInfo *itemNode)
{
    (*connectionInfo).isAvailable = 0;
    (*connectionInfo).isServer = itemNode->sideType;
    (*connectionInfo).type = CONNECT_BR;
    if (strcpy_s((*connectionInfo).info.brInfo.brMac, BT_MAC_LEN, itemNode->mac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "InitConnInfo scpy error");
        return SOFTBUS_BRCONNECTION_STRNCPY_ERROR;
    }
    return SOFTBUS_OK;
}

int32_t GetBrRequestListByConnId(uint32_t connId, ListNode *notifyList,
    ConnectionInfo *connectionInfo, int32_t *sideType)
{
    int32_t packRequestFlag = 0;
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BrClient lock mutex failed");
        return packRequestFlag;
    }
    ListNode *britem = NULL;
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    RequestInfo *requestInfo = NULL;
    LIST_FOR_EACH(britem, &g_connection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(britem, BrConnectionInfo, node);
        if (itemNode->connectionId == connId) {
            (void)InitConnectionInfo(connectionInfo, itemNode);
            (*sideType) = itemNode->sideType;
            LIST_FOR_EACH_SAFE(item, itemNext, &itemNode->requestList) {
                requestInfo = LIST_ENTRY(item, RequestInfo, node);
                ListDelete(&requestInfo->node);
                ListAdd(notifyList, &requestInfo->node);
                packRequestFlag++;
            }
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return packRequestFlag;
}

bool HasDiffMacDeviceExit(const ConnectOption *option)
{
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return true;
    }
    if (IsListEmpty(&g_connection_list)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[g_connection_list is empty, allow to connect device.]");
        (void)pthread_mutex_unlock(&g_connectionLock);
        return false;
    }
    ListNode *item = NULL;
    bool res = false;
    LIST_FOR_EACH(item, &g_connection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->sideType == BR_CLIENT_TYPE) {
            if (memcmp(itemNode->mac, option->info.brOption.brMac, sizeof(itemNode->mac)) != 0) {
                res = true;
                break;
            }
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return res;
}

int32_t GetBrConnStateByConnOption(const ConnectOption *option, int32_t *outCountId)
{
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return BR_CONNECTION_STATE_CLOSED;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        BrConnectionInfo *itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (strncmp(itemNode->mac, option->info.brOption.brMac, BT_MAC_LEN) == 0) {
            if (outCountId != NULL) {
                *outCountId = itemNode->connectionId;
            }
            (void)pthread_mutex_unlock(&g_connectionLock);
            return itemNode->state;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return BR_CONNECTION_STATE_CLOSED;
}

bool IsBrDeviceReady(uint32_t connId)
{
    (void)pthread_mutex_lock(&g_connectionLock);
    ListNode *item = NULL;
    BrConnectionInfo *itemNode = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (itemNode->connectionId != connId) {
            continue;
        }
        if (itemNode->state != BR_CONNECTION_STATE_CONNECTED) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br state not connected, state: %d", itemNode->state);
            (void)pthread_mutex_unlock(&g_connectionLock);
            return false;
        }
        (void)pthread_mutex_unlock(&g_connectionLock);
        return true;
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return false;
}

int32_t BrClosingByConnOption(const ConnectOption *option, int32_t *socketFd, int32_t *sideType)
{
    if (pthread_mutex_lock(&g_connectionLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "mutex failed");
        return SOFTBUS_ERR;
    }

    ListNode *item = NULL;
    BrConnectionInfo *itemNode = NULL;
    LIST_FOR_EACH(item, &g_connection_list) {
        itemNode = LIST_ENTRY(item, BrConnectionInfo, node);
        if (memcmp(itemNode->mac, option->info.brOption.brMac, sizeof(itemNode->mac)) == 0) {
            *socketFd = itemNode->socketFd;
            *sideType = itemNode->sideType;
            itemNode->state = BR_CONNECTION_STATE_CLOSING;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_connectionLock);
    return SOFTBUS_OK;
}
