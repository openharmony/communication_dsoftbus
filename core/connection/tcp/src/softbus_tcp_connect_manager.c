/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "softbus_tcp_connect_manager.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_tcp_socket.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"

#define INVALID_DATA (-1)

static int32_t g_tcpMaxConnNum;
static int32_t g_tcpTimeOut;
static int32_t g_tcpMaxLen;
static char g_localIp[IP_LEN];

typedef struct TcpConnInfoNode {
    ListNode node;
    uint32_t connectionId;
    ConnectionInfo info;
} TcpConnInfoNode;

static SoftBusList *g_tcpConnInfoList = NULL;
static SoftbusBaseListener *g_tcpListener = NULL;
static const ConnectCallback *g_tcpConnCallback;

static int32_t AddTcpConnInfo(TcpConnInfoNode *item);
static int32_t DelTcpConnInfo(uint32_t connectionId, ConnectionInfo *info);
static void DelAllConnInfo(void);
static int32_t TcpOnConnectEvent(int32_t events, int32_t cfd, const char *ip);
static int32_t TcpOnDataEvent(int32_t events, int32_t fd);

int32_t TcpGetConnNum(void)
{
    if (g_tcpConnInfoList == NULL) {
        return 0;
    }
    return g_tcpConnInfoList->cnt;
}

int32_t AddTcpConnInfo(TcpConnInfoNode *item)
{
    if (item == NULL || g_tcpConnInfoList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    TcpConnInfoNode *temp = NULL;
    if (pthread_mutex_lock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if ((int32_t)g_tcpConnInfoList->cnt >= g_tcpMaxConnNum) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Tcp out of max conn num.");
        (void)pthread_mutex_unlock(&g_tcpConnInfoList->lock);
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY(temp, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (temp->connectionId == item->connectionId) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "ConnectionId:%08x ready in ConnectionInfoList.", item->connectionId);
            (void)pthread_mutex_unlock(&g_tcpConnInfoList->lock);
            return SOFTBUS_ERR;
        }
    }
    ListInit(&item->node);
    ListAdd(&g_tcpConnInfoList->list, &item->node);
    g_tcpConnInfoList->cnt++;
    (void)pthread_mutex_unlock(&g_tcpConnInfoList->lock);
    return SOFTBUS_OK;
}

int32_t DelTcpConnInfo(uint32_t connectionId, ConnectionInfo *info)
{
    if (g_tcpConnInfoList == NULL) {
        return SOFTBUS_ERR;
    }
    TcpConnInfoNode *item = NULL;
    if (pthread_mutex_lock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (item->connectionId == connectionId) {
            if (info != NULL) {
                if (memcpy_s((void *)info, sizeof(ConnectionInfo), (void *)&item->info,
                    sizeof(ConnectionInfo)) != EOK) {
                    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s failed.");
                    (void)pthread_mutex_unlock(&g_tcpConnInfoList->lock);
                    return SOFTBUS_MEM_ERR;
                }
            }
            TcpShutDown(item->info.info.ipInfo.fd);
            ListDelete(&item->node);
            SoftBusFree(item);
            g_tcpConnInfoList->cnt--;
            (void)pthread_mutex_unlock(&g_tcpConnInfoList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&g_tcpConnInfoList->lock);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
        "DelTcpConnInfo failed. ConnectionId:%08x not found.", connectionId);
    return SOFTBUS_OK;
}

int32_t TcpOnConnectEvent(int32_t events, int32_t cfd, const char *ip)
{
    if (events == SOFTBUS_SOCKET_EXCEPTION) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Exception occurred");
        return SOFTBUS_ERR;
    }
    if (cfd < 0 || ip == NULL || g_tcpListener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    TcpConnInfoNode *tcpConnInfoNode = (TcpConnInfoNode *)SoftBusCalloc(sizeof(TcpConnInfoNode));
    if (tcpConnInfoNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "OnConnectEvent malloc TcpConnInfoNode");
        return SOFTBUS_MALLOC_ERR;
    }

    tcpConnInfoNode->connectionId = CalTcpConnectionId(cfd);
    tcpConnInfoNode->info.isAvailable = true;
    tcpConnInfoNode->info.isServer = true;
    tcpConnInfoNode->info.type = CONNECT_TCP;
    if (strcpy_s(tcpConnInfoNode->info.info.ipInfo.ip, IP_LEN, ip) != EOK) {
        goto EXIT;
    }
    tcpConnInfoNode->info.info.ipInfo.port = GetTcpSockPort(cfd);
    tcpConnInfoNode->info.info.ipInfo.fd = cfd;
    if (AddTrigger(PROXY, cfd, READ_TRIGGER) != SOFTBUS_OK) {
        goto EXIT;
    }
    if (AddTcpConnInfo(tcpConnInfoNode) != SOFTBUS_OK) {
        goto EXIT;
    }
    g_tcpConnCallback->OnConnected(tcpConnInfoNode->connectionId, &tcpConnInfoNode->info);
    return SOFTBUS_OK;

EXIT:
    SoftBusFree(tcpConnInfoNode);
    (void)DelTrigger(PROXY, cfd, READ_TRIGGER);
    TcpShutDown(cfd);
    return SOFTBUS_ERR;
}

static char *RecvData(const ConnPktHead *head, int32_t fd, int32_t len)
{
    uint32_t headSize = sizeof(ConnPktHead);
    ssize_t recvLen = 0;
    if (len > g_tcpMaxLen) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Tcp recv data out of max data length, shutdown");
        return NULL;
    }
    char *data = (char *)SoftBusCalloc(headSize + len);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Tcp recv data malloc err");
        return NULL;
    }
    if (memcpy_s(data, headSize, head, headSize) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Tcp recv data copy head failed");
        goto EXIT;
    }
    while (recvLen < len) {
        ssize_t n = RecvTcpData(fd, data + headSize + recvLen, len - recvLen, g_tcpTimeOut);
        if (n < 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "receiveData: error occurred![recvLen=%d][len=%d][errno=%d]", recvLen, len, errno);
            goto EXIT;
        }
        recvLen += n;
    }
    return data;
EXIT:
    SoftBusFree(data);
    return NULL;
}

int32_t TcpOnDataEvent(int32_t events, int32_t fd)
{
    if (g_tcpListener == NULL || events != SOFTBUS_SOCKET_IN) {
        return SOFTBUS_ERR;
    }
    uint32_t connectionId = CalTcpConnectionId(fd);
    ConnPktHead head;
    uint32_t headSize = sizeof(ConnPktHead);
    ssize_t bytes = RecvTcpData(fd, (char *)&head, headSize, g_tcpTimeOut);
    if (bytes <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "TcpOnDataEvent Disconnect fd:%d", fd);
        (void)DelTrigger(PROXY, fd, RW_TRIGGER);
        ConnectionInfo *info = SoftBusCalloc(sizeof(ConnectionInfo));
        if (DelTcpConnInfo(connectionId, info) == SOFTBUS_OK) {
            g_tcpConnCallback->OnDisconnected(connectionId, info);
        }
        SoftBusFree(info);
        return SOFTBUS_OK;
    } else if (bytes != (ssize_t)headSize) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Recv Head failed.");
        return SOFTBUS_ERR;
    }
    char *data = RecvData(&head, fd, head.len);
    if (data == NULL) {
        (void)DelTrigger(PROXY, fd, RW_TRIGGER);
        DelTcpConnInfo(connectionId, NULL);
        return SOFTBUS_ERR;
    }
    g_tcpConnCallback->OnDataReceived(connectionId, head.module, head.seq, data, headSize + head.len);
    SoftBusFree(data);
    return SOFTBUS_OK;
}

static void DelAllConnInfo(void)
{
    if (g_tcpConnInfoList == NULL) {
        return;
    }
    if (pthread_mutex_lock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    TcpConnInfoNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        (void)DelTrigger(PROXY, item->info.info.ipInfo.fd, RW_TRIGGER);
    }
    while (1) {
        if (IsListEmpty(&g_tcpConnInfoList->list)) {
            break;
        }
        item = LIST_ENTRY((&g_tcpConnInfoList->list)->next, TcpConnInfoNode, node);
        ListDelete(&item->node);
        TcpShutDown(item->info.info.ipInfo.fd);
        SoftBusFree(item);
        g_tcpConnInfoList->cnt--;
    }
    ListInit(&g_tcpConnInfoList->list);
    pthread_mutex_unlock(&g_tcpConnInfoList->lock);
}

uint32_t CalTcpConnectionId(int32_t fd)
{
    uint32_t connectType = (uint32_t)CONNECT_TCP;
    uint32_t connectionId = ((uint32_t)fd & 0xffff) | (connectType << CONNECT_TYPE_SHIFT);
    return connectionId;
}

int32_t TcpConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    if (result == NULL ||
        result->OnConnectFailed == NULL ||
        result->OnConnectSuccessed == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (option == NULL || option->type != CONNECT_TCP) {
        result->OnConnectFailed(requestId, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_INVALID_PARAM;
    }
    TcpConnInfoNode *tcpConnInfoNode = (TcpConnInfoNode *)SoftBusCalloc(sizeof(TcpConnInfoNode));
    if (tcpConnInfoNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc TcpConnInfoNode failed");
        result->OnConnectFailed(requestId, SOFTBUS_MALLOC_ERR);
        return SOFTBUS_MALLOC_ERR;
    }

    int32_t fd = OpenTcpClientSocket(option->info.ipOption.ip, "0.0.0.0", (uint16_t)option->info.ipOption.port);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "OpenTcpClient failed.");
        SoftBusFree(tcpConnInfoNode);
        result->OnConnectFailed(requestId, SOFTBUS_ERR);
        return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    }
    if (AddTrigger(PROXY, fd, READ_TRIGGER) != SOFTBUS_OK) {
        TcpShutDown(fd);
        SoftBusFree(tcpConnInfoNode);
        result->OnConnectFailed(requestId, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }

    uint32_t connectionId = CalTcpConnectionId(fd);
    tcpConnInfoNode->connectionId = connectionId;
    tcpConnInfoNode->info.isAvailable = true;
    tcpConnInfoNode->info.isServer = false;
    tcpConnInfoNode->info.type = CONNECT_TCP;
    tcpConnInfoNode->info.info.ipInfo.port = option->info.ipOption.port;
    tcpConnInfoNode->info.info.ipInfo.fd = fd;
    if (strcpy_s(tcpConnInfoNode->info.info.ipInfo.ip, IP_LEN, option->info.ipOption.ip) != EOK ||
        AddTcpConnInfo(tcpConnInfoNode) != SOFTBUS_OK) {
        (void)DelTrigger(PROXY, fd, READ_TRIGGER);
        TcpShutDown(fd);
        SoftBusFree(tcpConnInfoNode);
        result->OnConnectFailed(requestId, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }
    result->OnConnectSuccessed(requestId, tcpConnInfoNode->connectionId, &tcpConnInfoNode->info);
    return SOFTBUS_OK;
}

int32_t TcpDisconnectDevice(uint32_t connectionId)
{
    ConnectionInfo info;
    if (TcpGetConnectionInfo(connectionId, &info) != SOFTBUS_OK || !info.isAvailable) {
        return SOFTBUS_ERR;
    }
    (void)DelTrigger(PROXY, info.info.ipInfo.fd, RW_TRIGGER);
    return DelTcpConnInfo(connectionId, NULL);
}

int32_t TcpDisconnectDeviceNow(const ConnectOption *option)
{
    if (g_tcpConnInfoList == NULL) {
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TcpConnInfoNode *item = NULL;
    TcpConnInfoNode *itemPrev = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (strcmp(option->info.ipOption.ip, item->info.info.ipInfo.ip) == 0) {
            (void)DelTrigger(PROXY, item->info.info.ipInfo.fd, RW_TRIGGER);
        }
    }
    LIST_FOR_EACH_ENTRY(item, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        itemPrev = (TcpConnInfoNode *)LIST_ENTRY(item, TcpConnInfoNode, node)->node.prev;
        if (strcmp(option->info.ipOption.ip, item->info.info.ipInfo.ip) == 0) {
            TcpShutDown(item->info.info.ipInfo.fd);
            ListDelete(&item->node);
            SoftBusFree(item);
            g_tcpConnInfoList->cnt--;
            item = itemPrev;
        }
    }
    if (g_tcpConnInfoList->cnt == 0) {
        ListInit(&g_tcpConnInfoList->list);
    }
    pthread_mutex_unlock(&g_tcpConnInfoList->lock);
    return SOFTBUS_OK;
}

int32_t TcpPostBytes(uint32_t connectionId, const char *data, int32_t len, int32_t pid, int32_t flag)
{
    (void)pid;
    TcpConnInfoNode *item = NULL;
    if (data == NULL || len <= 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_tcpConnInfoList == NULL) {
        SoftBusFree((void*)data);
        return SOFTBUS_ERR;
    }
    int32_t fd = -1;
    if (pthread_mutex_lock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        SoftBusFree((void*)data);
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (item->connectionId == connectionId) {
            fd = item->info.info.ipInfo.fd;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_tcpConnInfoList->lock);
    if (fd == -1) {
        SoftBusFree((void*)data);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
            "TcpPostBytes failed, connectionId:%08x not found.", connectionId);
        return SOFTBUS_ERR;
    }
    int32_t bytes = SendTcpData(fd, data, len, flag);
    SoftBusFree((void*)data);
    if (bytes != len) {
        return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TcpGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    if (g_tcpConnInfoList == NULL) {
        return SOFTBUS_ERR;
    }
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "info is NULL.");
        return SOFTBUS_INVALID_PARAM;
    }
    TcpConnInfoNode *item = NULL;
    if (pthread_mutex_lock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (item->connectionId == connectionId) {
            int32_t ret = memcpy_s(info, sizeof(ConnectionInfo), &item->info, sizeof(ConnectionInfo));
            (void)pthread_mutex_unlock(&g_tcpConnInfoList->lock);
            if (ret != EOK) {
                return SOFTBUS_MEM_ERR;
            }
            return SOFTBUS_OK;
        }
    }
    info->isAvailable = false;
    (void)pthread_mutex_unlock(&g_tcpConnInfoList->lock);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConnectionId:%08x is not exists.", connectionId);
    return SOFTBUS_ERR;
}

int32_t TcpStartListening(const LocalListenerInfo *info)
{
    if (info == NULL || info->type != CONNECT_TCP) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_tcpListener == NULL) {
        g_tcpListener = (SoftbusBaseListener *)SoftBusCalloc(sizeof(SoftbusBaseListener));
        if (g_tcpListener == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc tcp listener failed");
            return SOFTBUS_MALLOC_ERR;
        }
        g_tcpListener->onConnectEvent = TcpOnConnectEvent;
        g_tcpListener->onDataEvent = TcpOnDataEvent;
    }
    int32_t rc = SetSoftbusBaseListener(PROXY, g_tcpListener);
    if (rc != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Set BaseListener Failed.");
        return rc;
    }
    if (strcpy_s(g_localIp, IP_LEN, info->info.ipListenerInfo.ip) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Get local ip addr failed.");
        return SOFTBUS_MEM_ERR;
    }

    rc = StartBaseListener(PROXY, g_localIp, info->info.ipListenerInfo.port, SERVER_MODE);
    return rc;
}

int32_t TcpStopListening(const LocalListenerInfo *info)
{
    if (info == NULL || g_tcpListener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = StopBaseListener(PROXY);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    DelAllConnInfo();
    DestroyBaseListener(PROXY);
    g_tcpListener = NULL;
    return SOFTBUS_OK;
}

static int32_t InitProperty(void)
{
    g_tcpMaxConnNum = INVALID_DATA;
    g_tcpTimeOut = INVALID_DATA;
    g_tcpMaxLen = INVALID_DATA;
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_TCP_MAX_CONN_NUM,
        (unsigned char*)&g_tcpMaxConnNum, sizeof(g_tcpMaxConnNum)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get tcp MaxConnNum fail");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "tcp MaxConnNum is %u", g_tcpMaxConnNum);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_TCP_MAX_LENGTH,
        (unsigned char*)&g_tcpMaxLen, sizeof(g_tcpMaxLen)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get tcp MaxLen fail");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "tcp MaxLen is %u", g_tcpMaxLen);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_TCP_TIME_OUT,
        (unsigned char*)&g_tcpTimeOut, sizeof(g_tcpTimeOut)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get tcp TimeOut fail");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "tcp TimeOut is %u", g_tcpTimeOut);
    if (g_tcpMaxConnNum == INVALID_DATA || g_tcpTimeOut == INVALID_DATA ||
        g_tcpMaxLen == INVALID_DATA) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot get brBuffSize");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

ConnectFuncInterface *ConnInitTcp(const ConnectCallback *callback)
{
    if (callback == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConnectCallback is NULL.");
        return NULL;
    }
    if (InitProperty() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Can not InitProperty");
        return NULL;
    }
    ConnectFuncInterface *interface = SoftBusCalloc(sizeof(ConnectFuncInterface));
    if (interface == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "InitTcp failed.");
        return NULL;
    }
    interface->ConnectDevice = TcpConnectDevice;
    interface->DisconnectDevice = TcpDisconnectDevice;
    interface->DisconnectDeviceNow = TcpDisconnectDeviceNow;
    interface->PostBytes = TcpPostBytes;
    interface->GetConnectionInfo = TcpGetConnectionInfo;
    interface->StartLocalListening = TcpStartListening;
    interface->StopLocalListening = TcpStopListening;
    g_tcpConnCallback = callback;

    if (g_tcpConnInfoList == NULL) {
        g_tcpConnInfoList = CreateSoftBusList();
        if (g_tcpConnInfoList == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Create tcpConnInfoList failed.");
            SoftBusFree(interface);
            return NULL;
        }
        g_tcpConnInfoList->cnt = 0;
    }
    if (g_tcpListener == NULL) {
        g_tcpListener = (SoftbusBaseListener *)SoftBusCalloc(sizeof(SoftbusBaseListener));
        if (g_tcpListener == NULL) {
            SoftBusFree(interface);
            DestroySoftBusList(g_tcpConnInfoList);
            g_tcpConnInfoList = NULL;
            return NULL;
        }
    }
    g_tcpListener->onConnectEvent = TcpOnConnectEvent;
    g_tcpListener->onDataEvent = TcpOnDataEvent;
    return interface;
}