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

#include "trans_tcp_direct_manager.h"

#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_tcp_socket.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_message.h"

#define HANDSHAKE_TIMEOUT 19

static SoftBusList *g_sessionConnList = NULL;
static pthread_mutex_t g_tdcChannelLock = PTHREAD_MUTEX_INITIALIZER;
static int32_t g_tdcChannelId = 0;

int32_t GenerateTdcChannelId(void)
{
    int32_t channelId;
    if (pthread_mutex_lock(&g_tdcChannelLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "generate tdc channel id lock failed");
        return INVALID_CHANNEL_ID;
    }
    channelId = g_tdcChannelId++;
    if (g_tdcChannelId < 0) {
        g_tdcChannelId = 0;
    }
    pthread_mutex_unlock(&g_tdcChannelLock);
    return channelId;
}

static void OnSesssionTimeOutProc(const SessionConn *node)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OnSesssionTimeOutProc: channelId = %d, side = %d",
        node->channelId, node->serverSide);
    if (node->serverSide == false) {
        if (TransTdcOnChannelOpenFailed(node->appInfo.myData.pkgName, node->channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify channel open fail err");
        }
    }

    int32_t fd = node->appInfo.fd;
    if (fd >= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "fd[%d] is shutdown", fd);
        DelTrigger(DIRECT_CHANNEL_SERVER, fd, RW_TRIGGER);
        TcpShutDown(fd);
    }
}

static void TransTdcTimerProc(void)
{
    SessionConn *removeNode = NULL;
    SessionConn *nextNode = NULL;

    if (g_sessionConnList == NULL || g_sessionConnList->cnt == 0) {
        return;
    }
    if (pthread_mutex_lock(&g_sessionConnList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_sessionConnList->list, SessionConn, node) {
        removeNode->timeout++;
        if (removeNode->status < TCP_DIRECT_CHANNEL_STATUS_CONNECTED) {
            if (removeNode->timeout >= HANDSHAKE_TIMEOUT) {
                removeNode->status = TCP_DIRECT_CHANNEL_STATUS_TIMEOUT;
                OnSesssionTimeOutProc(removeNode);

                ListDelete(&removeNode->node);
                g_sessionConnList->cnt--;
                SoftBusFree(removeNode);
            }
        }
    }
    (void)pthread_mutex_unlock(&g_sessionConnList->lock);
}

static int32_t OpenConnTcp(AppInfo *appInfo, const ConnectOption *connInfo)
{
    if (appInfo == NULL || connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid para.");
        return SOFTBUS_ERR;
    }
    char *ip = (char*)connInfo->info.ipOption.ip;
    char *myIp = NULL;
    int sessionPort = connInfo->info.ipOption.port;
    int fd = OpenTcpClientSocket(ip, myIp, sessionPort);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Open socket err.");
        return SOFTBUS_ERR;
    }

    return fd;
}

int32_t TransTdcAddSessionConn(SessionConn *conn)
{
    if (conn == NULL || g_sessionConnList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    pthread_mutex_lock(&(g_sessionConnList->lock));
    ListInit(&conn->node);
    ListTailInsert(&g_sessionConnList->list, &conn->node);
    g_sessionConnList->cnt++;
    pthread_mutex_unlock(&g_sessionConnList->lock);

    return SOFTBUS_OK;
}

void TransDelSessionConnById(int32_t channelId)
{
    if (g_sessionConnList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get tdc info fail, info list is null.");
        return;
    }

    SessionConn *item = NULL;
    SessionConn *next = NULL;
    pthread_mutex_lock(&g_sessionConnList->lock);
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_sessionConnList->list, SessionConn, node) {
        if (item->channelId == channelId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_sessionConnList->cnt--;
            pthread_mutex_unlock(&g_sessionConnList->lock);
            return;
        }
    }
    pthread_mutex_unlock(&g_sessionConnList->lock);

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get tdc info is null");
}

static SessionConn *CreateDefaultSession(const AppInfo *appInfo, const ConnectOption *connInfo)
{
    SessionConn *newConn = (SessionConn*)SoftBusMalloc(sizeof(SessionConn));
    if (newConn == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc fail.");
        return NULL;
    }

    if (memcpy_s(&newConn->appInfo, sizeof(AppInfo), appInfo, sizeof(AppInfo)) != EOK) {
        SoftBusFree(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s ip fail.");
        return NULL;
    }

    newConn->appInfo.fd = -1;
    newConn->serverSide = false;
    newConn->channelId = INVALID_CHANNEL_ID;
    if (strcpy_s(newConn->appInfo.peerData.ip, IP_LEN, (char*)connInfo->info.ipOption.ip) != EOK) {
        SoftBusFree(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s fail.");
        return NULL;
    }
    newConn->appInfo.peerData.port = connInfo->info.ipOption.port;
    newConn->status = TCP_DIRECT_CHANNEL_STATUS_HANDSHAKING;
    newConn->timeout = 0;
    return newConn;
}

int32_t TransOpenTcpDirectChannel(AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
{
    if (appInfo == NULL || connInfo == NULL || channelId == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "param is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }

    appInfo->routeType = WIFI_STA;
    SessionConn *newConn = (SessionConn*)CreateDefaultSession(appInfo, connInfo);
    if (newConn == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create defautl session fail.");
        return SOFTBUS_MALLOC_ERR;
    }

    int32_t fd = OpenConnTcp(appInfo, connInfo);
    if (fd < 0) {
        SoftBusFree(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "tcp connect fail.");
        return SOFTBUS_ERR;
    }
    *channelId = GenerateTdcChannelId();
    if (TransSrvAddDataBufNode(*channelId, fd) != SOFTBUS_OK) {
        SoftBusFree(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create databuf error.");
        return SOFTBUS_ERR;
    }
    newConn->appInfo.fd = fd;
    newConn->channelId = *channelId;

    if (TransTdcAddSessionConn(newConn) != SOFTBUS_OK) {
        TransSrvDelDataBufNode(*channelId);
        SoftBusFree(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add session conn fail.");
        return SOFTBUS_ERR;
    }
    if (AddTrigger(DIRECT_CHANNEL_SERVER, newConn->appInfo.fd, WRITE_TRIGGER) != SOFTBUS_OK) {
        TransDelSessionConnById(newConn->channelId);
        TransSrvDelDataBufNode(*channelId);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add trigger fail, delete session conn.");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

SessionConn *GetSessionConnById(int32_t channelId, SessionConn *conn)
{
    if (g_sessionConnList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get tdc intfo err, infoList is null.");
        return NULL;
    }
    SessionConn *connInfo = NULL;
    pthread_mutex_lock(&(g_sessionConnList->lock));
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->channelId == channelId) {
            if (conn != NULL) {
                (void)memcpy_s(conn, sizeof(SessionConn), connInfo, sizeof(SessionConn));
            }
            pthread_mutex_unlock(&g_sessionConnList->lock);
            return connInfo;
        }
    }
    pthread_mutex_unlock(&g_sessionConnList->lock);

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "can not get srv session conn info.");
    return NULL;
}

int32_t SetAppInfoById(int32_t channelId, const AppInfo *appInfo)
{
    if (g_sessionConnList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv get tdc sesson conn info err, list is null.");
        return SOFTBUS_ERR;
    }
    SessionConn *connInfo = NULL;
    pthread_mutex_lock(&(g_sessionConnList->lock));
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->channelId == channelId) {
            (void)memcpy_s(&connInfo->appInfo, sizeof(AppInfo), appInfo, sizeof(AppInfo));
            pthread_mutex_unlock(&g_sessionConnList->lock);
            return SOFTBUS_OK;
        }
    }
    pthread_mutex_unlock(&g_sessionConnList->lock);

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "can not get srv session conn info.");
    return SOFTBUS_ERR;
}

int32_t SetSessionConnStatusById(int32_t channelId, int32_t status)
{
    if (g_sessionConnList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv get tdc sesson conn info err, list is null.");
        return SOFTBUS_ERR;
    }
    SessionConn *connInfo = NULL;
    pthread_mutex_lock(&(g_sessionConnList->lock));
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->channelId == channelId) {
            connInfo->status = status;
            pthread_mutex_unlock(&g_sessionConnList->lock);
            return SOFTBUS_OK;
        }
    }
    pthread_mutex_unlock(&g_sessionConnList->lock);

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "can not get srv session conn info.");
    return SOFTBUS_ERR;
}

SessionConn *GetSessionConnByFd(int fd, SessionConn *conn)
{
    if (g_sessionConnList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get tdc intfo err, infoList is null.");
        return NULL;
    }
    SessionConn *connInfo = NULL;
    pthread_mutex_lock(&(g_sessionConnList->lock));
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->appInfo.fd == fd) {
            if (conn != NULL) {
                (void)memcpy_s(conn, sizeof(SessionConn), connInfo, sizeof(SessionConn));
            }
            pthread_mutex_unlock(&g_sessionConnList->lock);
            return connInfo;
        }
    }
    pthread_mutex_unlock(&g_sessionConnList->lock);

    return NULL;
}

void SetSessionKeyByChanId(int chanId, const char *sessionKey, int32_t keyLen)
{
    if (g_sessionConnList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get tdc intfo err, infoList is null.");
        return;
    }
    SessionConn *connInfo = NULL;
    pthread_mutex_lock(&(g_sessionConnList->lock));
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->channelId == chanId) {
            if (memcpy_s(connInfo->appInfo.sessionKey, sizeof(connInfo->appInfo.sessionKey), sessionKey,
                keyLen) != EOK) {
                pthread_mutex_unlock(&g_sessionConnList->lock);
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy error.");
                return;
            }
            pthread_mutex_unlock(&g_sessionConnList->lock);
            return;
        }
    }
    pthread_mutex_unlock(&g_sessionConnList->lock);
}

uint64_t TransTdcGetNewSeqId(void)
{
#define TRANS_SEQ_STEP 2
    static uint64_t seq = 0;
    seq += TRANS_SEQ_STEP;
    return seq;
}

SoftBusList *GetTdcInfoList(void)
{
    return g_sessionConnList;
}

void SetTdcInfoList(SoftBusList *sessionConnList)
{
    g_sessionConnList = sessionConnList;
    return;
}

int32_t TransTcpDirectInit(const IServerChannelCallBack *cb)
{
    if (TransSrvDataListInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "init srv trans tcp direct databuf list failed");
        return SOFTBUS_ERR;
    }
    if (TransTdcSetCallBack(cb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set srv trans tcp dierct call failed");
        return SOFTBUS_ERR;
    }
    if (RegisterTimeoutCallback(SOFTBUS_TCP_DIRECTCHANNEL_TIMER_FUN, TransTdcTimerProc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RegisterTimeoutCallback failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void TransTcpDirectDeinit(void)
{
    TransSrvDataListDeinit();
    (void)RegisterTimeoutCallback(SOFTBUS_TCP_DIRECTCHANNEL_TIMER_FUN, NULL);
}

void TransTdcDeathCallback(const char *pkgName)
{
    if (g_sessionConnList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get tdc info error, info list is null.");
        return;
    }

    SessionConn *conn = NULL;
    SessionConn *next = NULL;

    if (pthread_mutex_lock(&(g_sessionConnList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(conn, next, &g_sessionConnList->list, SessionConn, node) {
        if (strcmp(conn->appInfo.myData.pkgName, pkgName) == 0) {
            ListDelete(&conn->node);
            DelTrigger(DIRECT_CHANNEL_SERVER, conn->appInfo.fd, RW_TRIGGER);
            SoftBusFree(conn);
            g_sessionConnList->cnt--;
            continue;
        }
    }
    (void)pthread_mutex_unlock(&g_sessionConnList->lock);
}