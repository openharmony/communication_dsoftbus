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
#include <stdlib.h>

#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_tcp_socket.h"
#include "trans_tcp_direct_listener.h"
#include "trans_tcp_direct_message.h"

#define TCP_DIRECT_CHANNEL_OPEN_TIMEOUT 19

static SoftBusList *g_sessionConnList = NULL;

static int32_t InitTdcInfo(SessionConn *newConn)
{
    if (pthread_mutex_init(&(newConn->lock), NULL)) {
        LOG_ERR("create mutex lock fail.");
        return SOFTBUS_ERR;
    }

    if (TransTdcAddSessionConn(newConn, RW_TRIGGER) != SOFTBUS_OK) {
        TransTdcCloseSessionConn(newConn->channelId);
        LOG_ERR("TransTdc add sessionConn err.");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static void TransTdcTimerProc(void)
{
    SessionConn *removeNode = NULL;
    SessionConn *nextNode = NULL;

    if (g_sessionConnList == NULL || g_sessionConnList->cnt == 0) {
        return;
    }
    if (pthread_mutex_lock(&g_sessionConnList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_sessionConnList->list, SessionConn, node) {
        removeNode->timeout++;
        if (removeNode->status == TCP_DIRECT_CHANNEL_STATUS_HANDSHAKING) {
            if (removeNode->timeout >= TCP_DIRECT_CHANNEL_OPEN_TIMEOUT) {
                removeNode->status = TCP_DIRECT_CHANNEL_STATUS_HANDSHAKE_TIMEOUT;

                (void)pthread_mutex_unlock(&g_sessionConnList->lock);
                NotifyChannelOpenFailed(removeNode->channelId);
                pthread_mutex_lock(&g_sessionConnList->lock);

                ListDelete(&removeNode->node);
                g_sessionConnList->cnt--;
                int fd = removeNode->appInfo.fd;
                if (fd >= 0) {
                    LOG_INFO("fd[%d] is shutdown", fd);
                    DelTrigger(DIRECT_CHANNEL_SERVER, fd, removeNode->triggerType);
                    TcpShutDown(fd);
                }

                LOG_ERR("channel (%ld) handshake is timeout", removeNode->channelId);
                SoftBusFree(removeNode);
            }
        }
    }
    (void)pthread_mutex_unlock(&g_sessionConnList->lock);
}

static int32_t OpenConnTcp(AppInfo *appInfo, const ConnectOption *connInfo)
{
    if (appInfo == NULL || connInfo == NULL) {
        LOG_ERR("Invalid para.");
        return SOFTBUS_ERR;
    }
    char *ip = (char*)connInfo->info.ipOption.ip;
    char *myIp = NULL;
    int sessionPort = connInfo->info.ipOption.port;
    int fd = OpenTcpClientSocket(ip, myIp, sessionPort);
    if (fd < 0) {
        LOG_ERR("Open socket err.");
        return SOFTBUS_ERR;
    }

    return fd;
}

int32_t TransOpenTcpDirectChannel(AppInfo *appInfo, const ConnectOption *connInfo, int *fd)
{
    if (appInfo == NULL || connInfo == NULL || fd == NULL) {
        LOG_ERR("param is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }

    char *ip = (char*)connInfo->info.ipOption.ip;
    int sessionPort = connInfo->info.ipOption.port;
    appInfo->routeType = WIFI_STA;
    SessionConn *newConn = (SessionConn*)SoftBusMalloc(sizeof(SessionConn));
    if (newConn == NULL) {
        LOG_ERR("Malloc err.");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(&newConn->appInfo, sizeof(AppInfo), appInfo, sizeof(AppInfo)) != EOK) {
        SoftBusFree(newConn);
        LOG_ERR("Memcpy ip err.");
        return SOFTBUS_ERR;
    }
    newConn->appInfo.fd = -1;
    newConn->serverSide = false;
    newConn->channelId = INVALID_CHANNEL_ID;
    if (strcpy_s(newConn->appInfo.peerData.ip, IP_LEN, ip) != EOK) {
        SoftBusFree(newConn);
        LOG_ERR("strcpy_s err.");
        return SOFTBUS_ERR;
    }
    newConn->appInfo.peerData.port = sessionPort;
    newConn->status = TCP_DIRECT_CHANNEL_STATUS_HANDSHAKING;
    newConn->timeout = 0;

    if (InitTdcInfo(newConn) != SOFTBUS_OK) {
        SoftBusFree(newConn);
        return SOFTBUS_ERR;
    }

    *fd = OpenConnTcp(appInfo, connInfo);
    if (*fd <= 0) {
        TransCloseDirectChannel(newConn->channelId);
        SoftBusFree(newConn);
        LOG_ERR("OpenConnTcp err.");
        return SOFTBUS_ERR;
    }

    newConn->appInfo.fd = *fd;
    newConn->channelId = *fd;
    if (AddTrigger(DIRECT_CHANNEL_SERVER, newConn->appInfo.fd, RW_TRIGGER) != SOFTBUS_OK) {
        TransCloseDirectChannel(newConn->channelId);
        SoftBusFree(newConn);
        LOG_ERR("AddTrigger failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t TransCloseDirectChannel(int channelId)
{
    SessionConn *tdcInfo = GetTdcInfoByChannelId(channelId);
    if (tdcInfo == NULL) {
        LOG_ERR("SessionConn is not exit");
        return SOFTBUS_ERR;
    }
    TransTdcCloseSessionConn(channelId);
    SoftBusFree(tdcInfo);
    return SOFTBUS_OK;
}

int32_t TransTdcAddSessionConn(SessionConn *conn, TriggerType triggerType)
{
    if (conn == NULL || g_sessionConnList == NULL || TransTdcGetSessionListener() == NULL) {
        LOG_ERR("invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    pthread_mutex_lock(&(g_sessionConnList->lock));
    ListInit(&conn->node);
    ListTailInsert(&g_sessionConnList->list, &conn->node);
    g_sessionConnList->cnt++;
    pthread_mutex_unlock(&g_sessionConnList->lock);
    conn->triggerType = triggerType;
    conn->authStarted = false;
    conn->openChannelFinished = false;
    if (conn->appInfo.fd >= 0) {
        if (AddTrigger(DIRECT_CHANNEL_SERVER, conn->appInfo.fd, triggerType) != SOFTBUS_OK) {
            LOG_ERR("AddTrigger failed");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

void TransTdcStopSessionConn(int32_t channelId)
{
    SessionConn *tdcInfo = GetTdcInfoByChannelId(channelId);
    if (tdcInfo == NULL) {
        LOG_ERR("get tdc intfo err");
        return;
    }
    DelTrigger(DIRECT_CHANNEL_SERVER, tdcInfo->appInfo.fd, tdcInfo->triggerType);
    return;
}

void TransTdcCloseSessionConn(int32_t channelId)
{
    SessionConn *tdcInfo = GetTdcInfoByChannelId(channelId);
    if (tdcInfo == NULL || g_sessionConnList == NULL) {
        LOG_ERR("get tdc intfo err");
        return;
    }
    pthread_mutex_lock(&(g_sessionConnList->lock));
    ListDelete(&tdcInfo->node);
    g_sessionConnList->cnt--;
    pthread_mutex_unlock(&(g_sessionConnList->lock));
    int fd = tdcInfo->appInfo.fd;
    TransTdcStopSessionConn(tdcInfo->channelId);
    if (fd >= 0) {
        LOG_INFO("fd[%d] is shutdown", fd);
        TcpShutDown(fd);
    }
    NotifyChannelClosed(tdcInfo->channelId);
}

SessionConn *GetTdcInfoByChannelId(int32_t channelId)
{
    if (g_sessionConnList == NULL) {
        LOG_ERR("get tdc intfo err, infoList is null.");
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

    LOG_ERR("get tdc info is null");
    return NULL;
}

SessionConn *GetTdcInfoByFd(int fd)
{
    if (g_sessionConnList == NULL) {
        LOG_ERR("get tdc intfo err, infoList is null.");
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

int32_t TransTcpDirectInit(void)
{
    if (RegisterTimeoutCallback(SOFTBUS_TCP_DIRECTCHANNEL_TIMER_FUN, TransTdcTimerProc) != SOFTBUS_OK) {
        LOG_ERR("RegisterTimeoutCallback failed");
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
        LOG_ERR("get tdc info error, info list is null.");
        return;
    }

    SessionConn *connInfo = NULL;
    if (pthread_mutex_lock(&(g_sessionConnList->lock)) != 0) {
        LOG_ERR("lock mutex fail!");
        return;
    }
    LIST_FOR_EACH_ENTRY(connInfo, &g_sessionConnList->list, SessionConn, node) {
        if (connInfo != NULL && strcmp(connInfo->appInfo.myData.pkgName, pkgName) == 0) {
            TransTdcCloseSessionConn(connInfo->channelId);
            continue;
        }
    }
    (void)pthread_mutex_unlock(&g_sessionConnList->lock);
}