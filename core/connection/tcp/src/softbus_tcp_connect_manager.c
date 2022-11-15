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

#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
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
#define AUTH_P2P_KEEP_ALIVE_TIME 10

static int32_t g_tcpMaxConnNum;
static int32_t g_tcpTimeOut;
static uint32_t g_tcpMaxLen;

typedef struct {
    ListenerModule moduleId;
    SoftbusBaseListener listener;
} TcpListenerItem;

typedef struct TcpConnInfoNode {
    ListNode node;
    uint32_t connectionId;
    ConnectionInfo info;
    ConnectResult result;
    uint32_t requestId;
} TcpConnInfoNode;

static SoftBusList *g_tcpConnInfoList = NULL;
static const ConnectCallback *g_tcpConnCallback;
static ConnectFuncInterface g_tcpInterface;

static int32_t AddTcpConnInfo(TcpConnInfoNode *item);
static void DelTcpConnInfo(uint32_t connectionId);
static void DelAllConnInfo(ListenerModule moduleId);
static int32_t TcpOnConnectEvent(ListenerModule module, int32_t events, int32_t cfd, const char *ip);
static int32_t TcpOnDataEvent(int32_t events, int32_t fd);
static SoftbusBaseListener *CheckTcpListener(ListenerModule moduleId);

uint32_t TcpGetConnNum(void)
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
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if ((int32_t)g_tcpConnInfoList->cnt >= g_tcpMaxConnNum) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Tcp out of max conn num.");
        (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY(temp, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (temp->connectionId == item->connectionId) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "ConnectionId:%08x ready in ConnectionInfoList.", item->connectionId);
            (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
            return SOFTBUS_ERR;
        }
    }
    ListInit(&item->node);
    ListAdd(&g_tcpConnInfoList->list, &item->node);
    g_tcpConnInfoList->cnt++;
    (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
    return SOFTBUS_OK;
}

static void DelTcpConnInfo(uint32_t connectionId)
{
    if (g_tcpConnInfoList == NULL) {
        return;
    }
    TcpConnInfoNode *item = NULL;
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (item->connectionId == connectionId) {
            (void)DelTrigger(item->info.info.ipInfo.moduleId, item->info.info.ipInfo.fd, RW_TRIGGER);
            TcpShutDown(item->info.info.ipInfo.fd);
            ListDelete(&item->node);
            g_tcpConnInfoList->cnt--;
            (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
            g_tcpConnCallback->OnDisconnected(connectionId, &item->info);
            SoftBusFree(item);
            return;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
        "DelTcpConnInfo failed. ConnectionId:%08x not found.", connectionId);
    return;
}

static void DelTcpConnNode(uint32_t connectionId)
{
    if (g_tcpConnInfoList == NULL) {
        return;
    }
    TcpConnInfoNode *item = NULL;
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (item->connectionId == connectionId) {
            ListDelete(&item->node);
            g_tcpConnInfoList->cnt--;
            (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
            SoftBusFree(item);
            return;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
        "DelTcpConnNode failed. ConnectionId:%08x not found.", connectionId);
    return;
}

static int32_t TcpOnConnectEvent(ListenerModule module, int32_t events, int32_t cfd, const char *ip)
{
    if (events == SOFTBUS_SOCKET_EXCEPTION) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Exception occurred");
        return SOFTBUS_ERR;
    }
    if (cfd < 0 || ip == NULL) {
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
    tcpConnInfoNode->info.info.ipInfo.moduleId = module;
    if (AddTrigger(module, cfd, READ_TRIGGER) != SOFTBUS_OK) {
        goto EXIT;
    }
    if (AddTcpConnInfo(tcpConnInfoNode) != SOFTBUS_OK) {
        goto EXIT;
    }
    g_tcpConnCallback->OnConnected(tcpConnInfoNode->connectionId, &tcpConnInfoNode->info);
    return SOFTBUS_OK;

EXIT:
    SoftBusFree(tcpConnInfoNode);
    (void)DelTrigger(module, cfd, READ_TRIGGER);
    TcpShutDown(cfd);
    return SOFTBUS_ERR;
}

static char *RecvData(const ConnPktHead *head, int32_t fd, uint32_t len)
{
    uint32_t headSize = sizeof(ConnPktHead);
    uint32_t recvLen = 0;
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
                "receiveData: error occurred![recvLen=%d][len=%d]", recvLen, len);
            goto EXIT;
        }
        recvLen += (uint32_t)n;
    }
    return data;
EXIT:
    SoftBusFree(data);
    return NULL;
}

static int32_t GetTcpInfoByFd(int32_t fd, TcpConnInfoNode *tcpInfo)
{
    if (g_tcpConnInfoList == NULL) {
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_ERR;
    }
    TcpConnInfoNode *item = NULL;
    TcpConnInfoNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (item->info.info.ipInfo.fd == fd) {
            if (memcpy_s(tcpInfo, sizeof(TcpConnInfoNode), item, sizeof(TcpConnInfoNode)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetTcpInfoByFd:memcpy_s failed");
                return SOFTBUS_ERR;
            }
            (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
    return SOFTBUS_OK;
}

int32_t TcpOnDataEventOut(int32_t fd)
{
    TcpConnInfoNode tcpInfo = {0};

    if (GetTcpInfoByFd(fd, &tcpInfo) != SOFTBUS_OK) {
        (void)DelTrigger(tcpInfo.info.info.ipInfo.moduleId, fd, WRITE_TRIGGER);
        TcpShutDown(fd);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "TcpOnDataEventSocketOut fail %d", fd);
        return SOFTBUS_ERR;
    }
    int32_t ret = ConnGetSocketError(fd);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%d connect fail %d", fd, ret);
        tcpInfo.result.OnConnectFailed(tcpInfo.requestId, ret);
        (void)DelTrigger(tcpInfo.info.info.ipInfo.moduleId, fd, WRITE_TRIGGER);
        TcpShutDown(fd);
        DelTcpConnNode(tcpInfo.connectionId);
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "notfiy connect ok req %d", tcpInfo.requestId);
    tcpInfo.result.OnConnectSuccessed(tcpInfo.requestId, tcpInfo.connectionId, &tcpInfo.info);
    (void)DelTrigger(tcpInfo.info.info.ipInfo.moduleId, fd, WRITE_TRIGGER);
    (void)AddTrigger(tcpInfo.info.info.ipInfo.moduleId, fd, READ_TRIGGER);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "notfiy finish");
    return SOFTBUS_OK;
}

int32_t TcpOnDataEventIn(int32_t fd)
{
    uint32_t connectionId = CalTcpConnectionId(fd);
    ConnPktHead head;
    uint32_t headSize = sizeof(ConnPktHead);
    ssize_t bytes = RecvTcpData(fd, (char *)&head, headSize, g_tcpTimeOut);
    if (bytes <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "TcpOnDataEvent Disconnect fd:%d", fd);
        DelTcpConnInfo(connectionId);
        return SOFTBUS_OK;
    } else if (bytes != (ssize_t)headSize) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Recv Head failed.");
        return SOFTBUS_ERR;
    }
    char *data = RecvData(&head, fd, head.len);
    if (data == NULL) {
        DelTcpConnInfo(connectionId);
        return SOFTBUS_ERR;
    }
    g_tcpConnCallback->OnDataReceived(connectionId, head.module, head.seq, data, (int32_t)(headSize + head.len));
    SoftBusFree(data);
    return SOFTBUS_OK;
}

int32_t TcpOnDataEvent(int32_t events, int32_t fd)
{
    if (events == SOFTBUS_SOCKET_IN) {
        return TcpOnDataEventIn(fd);
    }

    if (events == SOFTBUS_SOCKET_OUT) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv tcp write events fd=%d", fd);
        return TcpOnDataEventOut(fd);
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv tcp invalid events=%d fd=%d", events, fd);
    uint32_t connectionId = CalTcpConnectionId(fd);
    DelTcpConnInfo(connectionId);
    return SOFTBUS_ERR;
}
static void DelAllConnInfo(ListenerModule moduleId)
{
    if (g_tcpConnInfoList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    TcpConnInfoNode *item = NULL;
    TcpConnInfoNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (item->info.info.ipInfo.moduleId == (int32_t)moduleId) {
            (void)DelTrigger(moduleId, item->info.info.ipInfo.fd, RW_TRIGGER);
            ListDelete(&item->node);
            TcpShutDown(item->info.info.ipInfo.fd);
            g_tcpConnCallback->OnDisconnected(item->connectionId, &item->info);
            SoftBusFree(item);
            g_tcpConnInfoList->cnt--;
        }
    }
    if (g_tcpConnInfoList->cnt == 0) {
        ListInit(&g_tcpConnInfoList->list);
    }

    SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
}

uint32_t CalTcpConnectionId(int32_t fd)
{
    uint32_t connectType = (uint32_t)CONNECT_TCP;
    uint32_t connectionId = ((uint32_t)fd & 0xffff) | (connectType << CONNECT_TYPE_SHIFT);
    return connectionId;
}

int32_t TcpConnectDeviceCheckArg(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    if (result == NULL ||
        result->OnConnectFailed == NULL ||
        result->OnConnectSuccessed == NULL) {
        return SOFTBUS_ERR;
    }
    if (option == NULL || option->type != CONNECT_TCP || CheckTcpListener(option->info.ipOption.moduleId) == NULL) {
        result->OnConnectFailed(requestId, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TcpConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    if (TcpConnectDeviceCheckArg(option, requestId, result) == SOFTBUS_ERR) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t fd = OpenTcpClientSocket(option->info.ipOption.ip, "0.0.0.0", (uint16_t)option->info.ipOption.port, false);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "OpenTcpClient failed.");
        result->OnConnectFailed(requestId, SOFTBUS_ERR);
        return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    }

    TcpConnInfoNode *tcpConnInfoNode = (TcpConnInfoNode *)SoftBusCalloc(sizeof(TcpConnInfoNode));
    if (tcpConnInfoNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc TcpConnInfoNode failed");
        TcpShutDown(fd);
        result->OnConnectFailed(requestId, SOFTBUS_MALLOC_ERR);
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(tcpConnInfoNode->info.info.ipInfo.ip, IP_LEN, option->info.ipOption.ip) != EOK ||
        memcpy_s(&tcpConnInfoNode->result, sizeof(ConnectResult), result, sizeof(ConnectResult)) != EOK) {
        TcpShutDown(fd);
        SoftBusFree(tcpConnInfoNode);
        result->OnConnectFailed(requestId, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }

    uint32_t connectionId = CalTcpConnectionId(fd);
    tcpConnInfoNode->requestId = requestId;
    tcpConnInfoNode->connectionId = connectionId;
    tcpConnInfoNode->info.isAvailable = true;
    tcpConnInfoNode->info.isServer = false;
    tcpConnInfoNode->info.type = CONNECT_TCP;
    tcpConnInfoNode->info.info.ipInfo.port = option->info.ipOption.port;
    tcpConnInfoNode->info.info.ipInfo.fd = fd;
    tcpConnInfoNode->info.info.ipInfo.moduleId = option->info.ipOption.moduleId;
    if (AddTcpConnInfo(tcpConnInfoNode) != SOFTBUS_OK) {
        TcpShutDown(fd);
        SoftBusFree(tcpConnInfoNode);
        result->OnConnectFailed(requestId, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }
    if (AddTrigger(option->info.ipOption.moduleId, fd, WRITE_TRIGGER) != SOFTBUS_OK) {
        TcpShutDown(fd);
        DelTcpConnNode(connectionId);
        result->OnConnectFailed(requestId, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "tcp connect add write trigger ok");
    return SOFTBUS_OK;
}

int32_t TcpDisconnectDevice(uint32_t connectionId)
{
    ConnectionInfo info;
    if (TcpGetConnectionInfo(connectionId, &info) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    DelTcpConnInfo(connectionId);
    return SOFTBUS_OK;
}

int32_t TcpDisconnectDeviceNow(const ConnectOption *option)
{
    if (g_tcpConnInfoList == NULL || option == NULL) {
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TcpConnInfoNode *item = NULL;
    TcpConnInfoNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (strcmp(option->info.ipOption.ip, item->info.info.ipInfo.ip) == 0) {
            (void)DelTrigger(item->info.info.ipInfo.moduleId, item->info.info.ipInfo.fd, RW_TRIGGER);
            TcpShutDown(item->info.info.ipInfo.fd);
            ListDelete(&item->node);
            g_tcpConnInfoList->cnt--;
            g_tcpConnCallback->OnDisconnected(item->connectionId, &item->info);
            SoftBusFree(item);
        }
    }
    if (g_tcpConnInfoList->cnt == 0) {
        ListInit(&g_tcpConnInfoList->list);
    }
    SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
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
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
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
    (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
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
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (item->connectionId == connectionId) {
            int32_t ret = memcpy_s(info, sizeof(ConnectionInfo), &item->info, sizeof(ConnectionInfo));
            (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
            if (ret != EOK) {
                return SOFTBUS_MEM_ERR;
            }
            return SOFTBUS_OK;
        }
    }
    info->isAvailable = false;
    (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConnectionId:%08x is not exists.", connectionId);
    return SOFTBUS_ERR;
}

static int32_t OnProxyServerConnectEvent(int32_t events, int32_t cfd, const char *ip)
{
    return TcpOnConnectEvent(PROXY, events, cfd, ip);
}

static int32_t OnAuthP2pServerConnectEvent(int32_t events, int32_t cfd, const char *ip)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv p2p conned %d", cfd);
    if (ConnSetTcpKeepAlive(cfd, AUTH_P2P_KEEP_ALIVE_TIME) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "set keepalive fail");
        TcpShutDown(cfd);
        return SOFTBUS_ERR;
    }
    return TcpOnConnectEvent(AUTH_P2P, events, cfd, ip);
}

static TcpListenerItem g_tcpListenerItems[] = {
    {
        .moduleId = PROXY,
        .listener = {
            .onConnectEvent = OnProxyServerConnectEvent,
            .onDataEvent = TcpOnDataEvent
        }
    },
    {
        .moduleId = AUTH_P2P,
        .listener = {
            .onConnectEvent = OnAuthP2pServerConnectEvent,
            .onDataEvent = TcpOnDataEvent
        }
    },
    /* Note: if add new tcp server, expend it here according to the above codes. */
};

static SoftbusBaseListener *CheckTcpListener(ListenerModule moduleId)
{
    for (uint32_t i = 0; i < sizeof(g_tcpListenerItems) / sizeof(TcpListenerItem); i++) {
        if (g_tcpListenerItems[i].moduleId == moduleId) {
            return &(g_tcpListenerItems[i].listener);
        }
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unsupport ListenerModule, id = %d.", moduleId);
    return NULL;
}

int32_t TcpStartListening(const LocalListenerInfo *info)
{
    if (info == NULL || info->type != CONNECT_TCP) {
        return SOFTBUS_INVALID_PARAM;
    }
    ListenerModule moduleId = info->info.ipListenerInfo.moduleId;
    SoftbusBaseListener *listener = CheckTcpListener(moduleId);
    if (listener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t rc = SetSoftbusBaseListener(moduleId, listener);
    if (rc != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Set BaseListener Failed.");
        return rc;
    }
    return StartBaseListener(moduleId, info->info.ipListenerInfo.ip, info->info.ipListenerInfo.port, SERVER_MODE);
}

int32_t TcpStopListening(const LocalListenerInfo *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    ListenerModule moduleId = info->info.ipListenerInfo.moduleId;
    if (CheckTcpListener(moduleId) == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = StopBaseListener(moduleId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    DelAllConnInfo(moduleId);
    DestroyBaseListener(moduleId);
    return SOFTBUS_OK;
}

static int32_t InitProperty(void)
{
    g_tcpMaxConnNum = INVALID_DATA;
    g_tcpTimeOut = INVALID_DATA;
    g_tcpMaxLen = 0;
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_TCP_MAX_CONN_NUM,
        (unsigned char*)&g_tcpMaxConnNum, sizeof(g_tcpMaxConnNum)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get tcp MaxConnNum fail");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "tcp MaxConnNum is %d", g_tcpMaxConnNum);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_TCP_MAX_LENGTH,
        (unsigned char*)&g_tcpMaxLen, sizeof(g_tcpMaxLen)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get tcp MaxLen fail");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "tcp MaxLen is %d", g_tcpMaxLen);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_TCP_TIME_OUT,
        (unsigned char*)&g_tcpTimeOut, sizeof(g_tcpTimeOut)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get tcp TimeOut fail");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "tcp TimeOut is %d", g_tcpTimeOut);
    if (g_tcpMaxConnNum == INVALID_DATA || g_tcpTimeOut == INVALID_DATA || g_tcpMaxLen == 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot get brBuffSize");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool TcpCheckActiveConnection(const ConnectOption *info)
{
    (void)info;
    return false;
}

static void InitTcpInterface(void)
{
    g_tcpInterface.ConnectDevice = TcpConnectDevice;
    g_tcpInterface.DisconnectDevice = TcpDisconnectDevice;
    g_tcpInterface.DisconnectDeviceNow = TcpDisconnectDeviceNow;
    g_tcpInterface.PostBytes = TcpPostBytes;
    g_tcpInterface.GetConnectionInfo = TcpGetConnectionInfo;
    g_tcpInterface.StartLocalListening = TcpStartListening;
    g_tcpInterface.StopLocalListening = TcpStopListening;
    g_tcpInterface.CheckActiveConnection = TcpCheckActiveConnection;
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
    InitTcpInterface();
    g_tcpConnCallback = callback;

    if (g_tcpConnInfoList == NULL) {
        g_tcpConnInfoList = CreateSoftBusList();
        if (g_tcpConnInfoList == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Create tcpConnInfoList failed.");
            return NULL;
        }
        g_tcpConnInfoList->cnt = 0;
    }
    return &g_tcpInterface;
}
