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

#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_tcp_socket.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_message.h"

#define HANDSHAKE_TIMEOUT 19

static SoftBusList *g_sessionConnList = NULL;

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

                (void)pthread_mutex_unlock(&g_sessionConnList->lock);
                NotifyChannelOpenFailed(removeNode->channelId);
                pthread_mutex_lock(&g_sessionConnList->lock);

                ListDelete(&removeNode->node);
                g_sessionConnList->cnt--;
                int fd = removeNode->appInfo.fd;
                if (fd >= 0) {
                    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "fd[%d] is shutdown", fd);
                    DelTrigger(DIRECT_CHANNEL_SERVER, fd, RW_TRIGGER);
                    TcpShutDown(fd);
                }

                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "channel[%d] handshake is timeout",
                    removeNode->channelId);
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
    conn->authStarted = false;
    conn->openChannelFinished = false;

    return SOFTBUS_OK;
}

void TransTdcStopListen(int32_t channelId)
{
    SessionConn *conn = GetTdcInfoByChannelId(channelId);
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get tdc intfo err");
        return;
    }
    DelTrigger(DIRECT_CHANNEL_SERVER, conn->appInfo.fd, conn->triggerType);
    return;
}

void TransTdcDelSessionConn(SessionConn *conn)
{
    if (conn == NULL || g_sessionConnList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "input illegal or session conn list illegal.");
        return;
    }

    pthread_mutex_lock(&g_sessionConnList->lock);
    ListDelete(&conn->node);
    SoftBusFree(conn);
    g_sessionConnList->cnt--;
    pthread_mutex_unlock(&g_sessionConnList->lock);
}

void TransTdcDelSessionConnByChannelId(int32_t channelId)
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
            return;
        }
    }
    pthread_mutex_unlock(&g_sessionConnList->lock);

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get tdc info is null");
}

int32_t TransOpenTcpDirectChannel(AppInfo *appInfo, const ConnectOption *connInfo, int *fd)
{
    if (appInfo == NULL || connInfo == NULL || fd == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "param is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }

    char *ip = (char*)connInfo->info.ipOption.ip;
    int sessionPort = connInfo->info.ipOption.port;
    appInfo->routeType = WIFI_STA;
    SessionConn *newConn = (SessionConn*)SoftBusMalloc(sizeof(SessionConn));
    if (newConn == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(&newConn->appInfo, sizeof(AppInfo), appInfo, sizeof(AppInfo)) != EOK) {
        SoftBusFree(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s ip fail.");
        return SOFTBUS_MEM_ERR;
    }
    newConn->appInfo.fd = -1;
    newConn->serverSide = false;
    newConn->channelId = INVALID_CHANNEL_ID;
    if (strcpy_s(newConn->appInfo.peerData.ip, IP_LEN, ip) != EOK) {
        SoftBusFree(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s fail.");
        return SOFTBUS_MEM_ERR;
    }
    newConn->appInfo.peerData.port = sessionPort;
    newConn->status = TCP_DIRECT_CHANNEL_STATUS_HANDSHAKING;
    newConn->timeout = 0;

    *fd = OpenConnTcp(appInfo, connInfo);
    if (*fd < 0) {
        SoftBusFree(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "tcp connect fail.");
        return SOFTBUS_ERR;
    }
    newConn->appInfo.fd = *fd;
    newConn->channelId = *fd;
    newConn->dataBuffer.w = newConn->dataBuffer.data;

    if (TransTdcAddSessionConn(newConn) != SOFTBUS_OK) {
        SoftBusFree(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add session conn fail.");
        return SOFTBUS_ERR;
    }
    if (AddTrigger(DIRECT_CHANNEL_SERVER, newConn->appInfo.fd, WRITE_TRIGGER) != SOFTBUS_OK) {
        TransTdcDelSessionConn(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add trigger fail, delete session conn.");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

SessionConn *GetTdcInfoByChannelId(int32_t channelId)
{
    if (g_sessionConnList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get tdc intfo err, infoList is null.");
        return NULL;
    }
    SessionConn *connInfo = NULL;
    pthread_mutex_lock(&(g_sessionConnList->lock));
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->channelId == channelId) {
            pthread_mutex_unlock(&g_sessionConnList->lock);
            return connInfo;
        }
    }
    pthread_mutex_unlock(&g_sessionConnList->lock);

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get tdc info is null");
    return NULL;
}

SessionConn *GetTdcInfoByFd(int fd)
{
    if (g_sessionConnList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get tdc intfo err, infoList is null.");
        return NULL;
    }
    SessionConn *connInfo = NULL;
    pthread_mutex_lock(&(g_sessionConnList->lock));
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo->appInfo.fd == fd) {
            pthread_mutex_unlock(&g_sessionConnList->lock);
            return connInfo;
        }
    }
    pthread_mutex_unlock(&g_sessionConnList->lock);

    return NULL;
}

uint64_t TransTdcGetNewSeqId(bool serverSide)
{
#define TRANS_SEQ_STEP 2
    static uint64_t seq = 0;
    seq += TRANS_SEQ_STEP;
    if (serverSide) {
        return seq + 1;
    }
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
    if (TransTdcSetCallBack(cb) != SOFTBUS_OK) {
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