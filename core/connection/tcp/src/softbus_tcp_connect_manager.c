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

#include <stdio.h>
#include "securec.h"

#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_datahead_transform.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_socket.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"
#include "softbus_hidumper_conn.h"
#include "softbus_hisysevt_connreporter.h"
#include "conn_event.h"

#define INVALID_DATA (-1)
#define AUTH_P2P_KEEP_ALIVE_TIME 10

#define TCP_CONNECT_INFO "tcpConnectInfo"

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
    ConnectStatistics statistics;
} TcpConnInfoNode;

static SoftBusList *g_tcpConnInfoList = NULL;
static const ConnectCallback *g_tcpConnCallback;
static ConnectFuncInterface g_tcpInterface;

static int32_t AddTcpConnInfo(TcpConnInfoNode *item);
static void DelTcpConnInfo(uint32_t connectionId, ListenerModule module, int32_t fd);
static void DelAllConnInfo(ListenerModule moduleId);
static int32_t TcpOnConnectEvent(ListenerModule module, int32_t cfd, const ConnectOption *clientAddr);
static int32_t TcpOnDataEvent(ListenerModule module, int32_t events, int32_t fd);
static int TcpConnectInfoDump(int fd);

static void DfxRecordTcpConnectFail(uint32_t pId, ConnectOption *option, TcpConnInfoNode *tcpInfo,
    ConnectStatistics *statistics, int32_t reason)
{
    if (statistics == NULL) {
        CONN_LOGW(CONN_COMMON, "statistics is null");
        return;
    }

    CONN_LOGI(CONN_COMMON, "record tcp conn fail, connectTraceId=%u, reason=%d", statistics->connectTraceId, reason);
    uint64_t costTime = SoftBusGetSysTimeMs() - statistics->startTime;
    SoftbusRecordConnResult(pId, SOFTBUS_HISYSEVT_CONN_TYPE_TCP, SOFTBUS_EVT_CONN_FAIL, costTime, reason);
}

static void DfxRecordTcpConnectSuccess(uint32_t pId, TcpConnInfoNode *tcpInfo, ConnectStatistics *statistics)
{
    if (statistics == NULL) {
        CONN_LOGI(CONN_COMMON, "statistics is null");
        return;
    }

    CONN_LOGI(CONN_COMMON, "record tcp conn success, connectTraceId=%u", statistics->connectTraceId);
    uint64_t costTime = SoftBusGetSysTimeMs() - statistics->startTime;
    SoftbusRecordConnResult(pId, SOFTBUS_HISYSEVT_CONN_TYPE_TCP, SOFTBUS_EVT_CONN_SUCC, costTime,
                            SOFTBUS_HISYSEVT_CONN_OK);
}

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
        CONN_LOGE(CONN_COMMON, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if ((int32_t)g_tcpConnInfoList->cnt >= g_tcpMaxConnNum) {
        CONN_LOGE(CONN_COMMON, "Tcp out of max conn num.");
        (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY(temp, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (temp->connectionId == item->connectionId) {
            CONN_LOGE(CONN_COMMON, "ConnectionId:%08x ready in ConnectionInfoList.", item->connectionId);
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

static void DelTcpConnInfo(uint32_t connectionId, ListenerModule module, int32_t fd)
{
    CONN_CHECK_AND_RETURN_LOGE(g_tcpConnInfoList, CONN_COMMON, "global connection list is null");
    int32_t status = SoftBusMutexLock(&g_tcpConnInfoList->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "lock failed, connid=%u, error=%d", connectionId, status);
        return;
    }

    TcpConnInfoNode *target = NULL;
    TcpConnInfoNode *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (it->connectionId == connectionId) {
            target = it;
            break;
        }
    }
    if (target != NULL) {
        ListDelete(&target->node);
        status = DelTrigger((ListenerModule)target->info.socketInfo.moduleId,
            target->info.socketInfo.fd, RW_TRIGGER);
        if (status != SOFTBUS_TCPFD_NOT_IN_TRIGGER) {
            ConnShutdownSocket(it->info.socketInfo.fd);
        }
        g_tcpConnInfoList->cnt--;
        (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
        g_tcpConnCallback->OnDisconnected(connectionId, &target->info);
        SoftBusFree(target);
        return;
    }
    (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);

    CONN_LOGE(CONN_COMMON, "delete tcp conn failed. connid=%u not found, module=%d, fd=%d", connectionId, module, fd);
    if (module >= UNUSE_BUTT || module < 0 || fd < 0) {
        return;
    }
    status = DelTrigger(module, fd, RW_TRIGGER);
    if (status != SOFTBUS_TCPFD_NOT_IN_TRIGGER) {
        ConnShutdownSocket(fd);
    }
}

static void DelTcpConnNode(uint32_t connectionId)
{
    if (g_tcpConnInfoList == NULL) {
        return;
    }
    TcpConnInfoNode *item = NULL;
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
        CONN_LOGE(CONN_COMMON, "lock failed");
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
    CONN_LOGE(CONN_COMMON, "DelTcpConnNode failed. ConnectionId:%08x not found.", connectionId);
    return;
}

static int32_t TcpOnConnectEvent(ListenerModule module, int32_t cfd, const ConnectOption *clientAddr)
{
    if (cfd < 0 || clientAddr == NULL) {
        CONN_LOGE(CONN_COMMON, "cfd=%d is invalid or clientAddr is null", cfd);
        return SOFTBUS_INVALID_PARAM;
    }

    if (module == AUTH_P2P) {
        CONN_LOGI(CONN_COMMON, "recv p2p conned %d", cfd);
        if (ConnSetTcpKeepAlive(cfd, AUTH_P2P_KEEP_ALIVE_TIME) != 0) {
            CONN_LOGE(CONN_COMMON, "set keepalive fail");
            ConnShutdownSocket(cfd);
            return SOFTBUS_ERR;
        }
    }

    TcpConnInfoNode *tcpConnInfoNode = (TcpConnInfoNode *)SoftBusCalloc(sizeof(TcpConnInfoNode));
    if (tcpConnInfoNode == NULL) {
        CONN_LOGE(CONN_COMMON, "malloc TcpConnInfoNode");
        return SOFTBUS_MALLOC_ERR;
    }

    tcpConnInfoNode->connectionId = CalTcpConnectionId(cfd);
    tcpConnInfoNode->info.isAvailable = true;
    tcpConnInfoNode->info.isServer = true;
    tcpConnInfoNode->info.type = CONNECT_TCP;
    if (strcpy_s(tcpConnInfoNode->info.socketInfo.addr, sizeof(tcpConnInfoNode->info.socketInfo.addr),
            clientAddr->socketOption.addr) != EOK) {
        goto EXIT;
    }
    tcpConnInfoNode->info.socketInfo.port = clientAddr->socketOption.port;
    tcpConnInfoNode->info.socketInfo.fd = cfd;
    tcpConnInfoNode->info.socketInfo.moduleId = module;
    tcpConnInfoNode->info.socketInfo.protocol = clientAddr->socketOption.protocol;
    if (AddTrigger(module, cfd, READ_TRIGGER) != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "add trigger failed, module=%d, cfd=%d, READ_TRIGGER", module, cfd);
        goto EXIT;
    }
    if (AddTcpConnInfo(tcpConnInfoNode) != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "add tcp conninfo failed");
        goto EXIT;
    }
    g_tcpConnCallback->OnConnected(tcpConnInfoNode->connectionId, &tcpConnInfoNode->info);
    return SOFTBUS_OK;

EXIT:
    SoftBusFree(tcpConnInfoNode);
    (void)DelTrigger(module, cfd, READ_TRIGGER);
    ConnShutdownSocket(cfd);
    return SOFTBUS_ERR;
}

static char *RecvData(const ConnPktHead *head, int32_t fd, uint32_t len)
{
    uint32_t headSize = sizeof(ConnPktHead);
    uint32_t recvLen = 0;
    if (len > g_tcpMaxLen) {
        CONN_LOGW(CONN_COMMON, "Tcp recv data out of max data length, shutdown");
        return NULL;
    }
    char *data = (char *)SoftBusCalloc(headSize + len);
    if (data == NULL) {
        CONN_LOGE(CONN_COMMON, "Tcp recv data malloc err");
        return NULL;
    }
    if (memcpy_s(data, headSize, head, headSize) != EOK) {
        CONN_LOGE(CONN_COMMON, "Tcp recv data copy head failed");
        goto EXIT;
    }
    while (recvLen < len) {
        ssize_t n = ConnRecvSocketData(fd, data + headSize + recvLen, len - recvLen, g_tcpTimeOut);
        if (n < 0) {
            CONN_LOGE(CONN_COMMON, "receiveData: error occurred![recvLen=%d][len=%d]", recvLen, len);
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
        CONN_LOGE(CONN_COMMON, "lock failed");
        return SOFTBUS_ERR;
    }
    TcpConnInfoNode *item = NULL;
    TcpConnInfoNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (item->info.socketInfo.fd == fd) {
            if (memcpy_s(tcpInfo, sizeof(TcpConnInfoNode), item, sizeof(TcpConnInfoNode)) != EOK) {
                CONN_LOGE(CONN_COMMON, "GetTcpInfoByFd:memcpy_s failed");
                return SOFTBUS_ERR;
            }
            (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
    return SOFTBUS_ERR;
}

static int32_t TcpOnDataEventOut(ListenerModule module, int32_t fd)
{
    (void)module;
    TcpConnInfoNode tcpInfo;
    (void)memset_s(&tcpInfo, sizeof(tcpInfo), 0, sizeof(tcpInfo));

    if (GetTcpInfoByFd(fd, &tcpInfo) != SOFTBUS_OK) {
        tcpInfo.info.socketInfo.moduleId = UNUSE_BUTT;
        (void)DelTrigger((ListenerModule)(tcpInfo.info.socketInfo.moduleId), fd, WRITE_TRIGGER);
        ConnShutdownSocket(fd);
        CONN_LOGI(CONN_COMMON, "TcpOnDataEventSocketOut fail %d", fd);
        return SOFTBUS_ERR;
    }
    int32_t ret = ConnGetSocketError(fd);
    if (ret != 0) {
        CONN_LOGW(CONN_COMMON, "%d connect fail %d", fd, ret);
        tcpInfo.result.OnConnectFailed(tcpInfo.requestId, ret);
        tcpInfo.statistics.reqId = tcpInfo.requestId;
        DfxRecordTcpConnectFail(
            DEFAULT_PID, NULL, &tcpInfo, &tcpInfo.statistics, SOFTBUS_HISYSEVT_TCP_CONNECTION_SOCKET_ERR);
        (void)DelTrigger((ListenerModule)(tcpInfo.info.socketInfo.moduleId), fd, WRITE_TRIGGER);
        DelTcpConnNode(tcpInfo.connectionId);
        ConnShutdownSocket(fd);
        return SOFTBUS_OK;
    }
    CONN_LOGI(CONN_COMMON, "notfiy connect ok req %d", tcpInfo.requestId);
    DfxRecordTcpConnectSuccess(DEFAULT_PID, &tcpInfo, &tcpInfo.statistics);
    tcpInfo.result.OnConnectSuccessed(tcpInfo.requestId, tcpInfo.connectionId, &tcpInfo.info);
    (void)DelTrigger((ListenerModule)(tcpInfo.info.socketInfo.moduleId), fd, WRITE_TRIGGER);
    (void)AddTrigger((ListenerModule)(tcpInfo.info.socketInfo.moduleId), fd, READ_TRIGGER);
    CONN_LOGI(CONN_COMMON, "notfiy finish");
    return SOFTBUS_OK;
}

static int32_t TcpOnDataEventIn(ListenerModule module, int32_t fd)
{
    uint32_t connectionId = CalTcpConnectionId(fd);
    ConnPktHead head = {0};
    uint32_t headSize = sizeof(ConnPktHead);
    ssize_t bytes = ConnRecvSocketData(fd, (char *)&head, headSize, g_tcpTimeOut);
    UnpackConnPktHead(&head);
    if (bytes < 0) {
        CONN_LOGI(CONN_COMMON, "TcpOnDataEvent Disconnect fd:%d", fd);
        DelTcpConnInfo(connectionId, module, fd);
        return SOFTBUS_OK;
    } else if (bytes != (ssize_t)headSize) {
        CONN_LOGE(CONN_COMMON, "Recv Head failed.");
        return SOFTBUS_ERR;
    }
    char *data = RecvData(&head, fd, head.len);
    if (data == NULL) {
        DelTcpConnInfo(connectionId, module, fd);
        return SOFTBUS_ERR;
    }
    g_tcpConnCallback->OnDataReceived(connectionId, (ConnModule)(head.module),
        head.seq, data, (int32_t)(headSize + head.len));
    SoftBusFree(data);
    return SOFTBUS_OK;
}

int32_t TcpOnDataEvent(ListenerModule module, int32_t events, int32_t fd)
{
    (void)module;
    if (events == SOFTBUS_SOCKET_IN) {
        return TcpOnDataEventIn(module, fd);
    }

    if (events == SOFTBUS_SOCKET_OUT) {
        CONN_LOGI(CONN_COMMON, "recv tcp write events fd=%d", fd);
        return TcpOnDataEventOut(module, fd);
    }
    CONN_LOGI(CONN_COMMON, "recv tcp invalid events=%d fd=%d", events, fd);
    uint32_t connectionId = CalTcpConnectionId(fd);
    DelTcpConnInfo(connectionId, module, fd);
    return SOFTBUS_ERR;
}
static void DelAllConnInfo(ListenerModule moduleId)
{
    if (g_tcpConnInfoList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
        CONN_LOGE(CONN_COMMON, "lock failed");
        return;
    }
    TcpConnInfoNode *item = NULL;
    TcpConnInfoNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (item->info.socketInfo.moduleId == (int32_t)moduleId) {
            (void)DelTrigger(moduleId, item->info.socketInfo.fd, RW_TRIGGER);
            ListDelete(&item->node);
            ConnShutdownSocket(item->info.socketInfo.fd);
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

int32_t TcpConnectDeviceCheckArg(const ConnectOption *option, uint32_t requestId,
    const ConnectResult *result)
{
    if ((result == NULL) ||
        (result->OnConnectFailed == NULL) ||
        (result->OnConnectSuccessed == NULL)) {
        CONN_LOGW(CONN_COMMON, "result or result member is null");
        return SOFTBUS_ERR;
    }
    if ((option == NULL) || (option->type != CONNECT_TCP)) {
        CONN_LOGW(CONN_COMMON, "option is null or type is mismatched");
        result->OnConnectFailed(requestId, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t WrapperAddTcpConnInfo(const ConnectOption *option, const ConnectResult *result, uint32_t connectionId,
                                     uint32_t requestId, int32_t fd, ConnectStatistics statistics)
{
    TcpConnInfoNode *tcpConnInfoNode = (TcpConnInfoNode *)SoftBusCalloc(sizeof(TcpConnInfoNode));
    if (tcpConnInfoNode == NULL) {
        CONN_LOGE(CONN_COMMON, "malloc TcpConnInfoNode failed");
        return SOFTBUS_MALLOC_ERR;
    }

    if (strcpy_s(tcpConnInfoNode->info.socketInfo.addr, sizeof(tcpConnInfoNode->info.socketInfo.addr),
            option->socketOption.addr) != EOK ||
        memcpy_s(&tcpConnInfoNode->result, sizeof(ConnectResult), result, sizeof(ConnectResult)) != EOK) {
        CONN_LOGE(CONN_COMMON, "copy TcpConnInfoNode failed");
        SoftBusFree(tcpConnInfoNode);
        return SOFTBUS_ERR;
    }

    tcpConnInfoNode->requestId = requestId;
    tcpConnInfoNode->connectionId = connectionId;
    tcpConnInfoNode->info.isAvailable = true;
    tcpConnInfoNode->info.isServer = false;
    tcpConnInfoNode->info.type = CONNECT_TCP;
    tcpConnInfoNode->info.socketInfo.port = option->socketOption.port;
    tcpConnInfoNode->info.socketInfo.protocol = option->socketOption.protocol;
    tcpConnInfoNode->info.socketInfo.fd = fd;
    tcpConnInfoNode->info.socketInfo.moduleId = option->socketOption.moduleId;
    tcpConnInfoNode->statistics = statistics;
    if (AddTcpConnInfo(tcpConnInfoNode) != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "AddTcpConnInfo failed");
        SoftBusFree(tcpConnInfoNode);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t TcpOpenClientSocketErr(const ConnectOption *option, uint32_t requestId,
    ConnectStatistics *statistics, const ConnectResult *result)
{
    ConnAlarmExtra extraAlarm = {
        .linkType = CONNECT_TCP,
        .errcode = SOFTBUS_TCPCONNECTION_SOCKET_ERR,
    };
    CONN_ALARM(CONNECTION_FAIL_ALARM, MANAGE_ALARM_TYPE, extraAlarm);
    CONN_LOGE(CONN_COMMON, "OpenTcpClient failed.");
    result->OnConnectFailed(requestId, SOFTBUS_ERR);
    statistics->reqId = requestId;
    DfxRecordTcpConnectFail(
        DEFAULT_PID, (ConnectOption *)option, NULL, statistics, SOFTBUS_HISYSEVT_TCP_CONNECTION_SOCKET_ERR);
    SoftBusFree(statistics);
    return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
}

int32_t TcpConnectDevice(const ConnectOption *option, uint32_t requestId,
    const ConnectResult *result)
{
    if (TcpConnectDeviceCheckArg(option, requestId, result) == SOFTBUS_ERR) {
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectStatistics *statistics = (ConnectStatistics *)SoftBusCalloc(sizeof(ConnectStatistics));
    CONN_CHECK_AND_RETURN_RET_LOGE(statistics != NULL, SOFTBUS_MALLOC_ERR, CONN_COMMON,
        "calloc ConnectStatistics fail");
    statistics->startTime = SoftBusGetSysTimeMs();
    statistics->connectTraceId = SoftbusGetConnectTraceId();
    CONN_LOGI(CONN_COMMON, "tcp conn start connectTraceId=%u", statistics->connectTraceId);
    ConnEventExtra extra = {
        .requestId = (int32_t)requestId,
        .peerWifiMac = option->socketOption.addr,
        .result = EVENT_STAGE_RESULT_OK
    };
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_INVOKE_PROTOCOL, extra);
    int32_t fd = ConnOpenClientSocket(option, BIND_ADDR_ALL, true);
    if (fd < 0) {
        return TcpOpenClientSocketErr(option, requestId, statistics, result);
    }

    int32_t error = SOFTBUS_HISYSEVT_TCP_CONNECTION_SOCKET_ERR;
    if (option->socketOption.keepAlive == 1) {
        if (ConnSetTcpKeepAlive(fd, AUTH_P2P_KEEP_ALIVE_TIME) != 0) {
            CONN_LOGE(CONN_COMMON, "set keepalive fail, fd: %d", fd);
            ConnShutdownSocket(fd);
            result->OnConnectFailed(requestId, SOFTBUS_ERR);
            DfxRecordTcpConnectFail(DEFAULT_PID, (ConnectOption *)option, NULL, statistics, error);
            SoftBusFree(statistics);
            return SOFTBUS_ERR;
        }
        CONN_LOGI(CONN_COMMON, "set keepalive successfully, fd: %d", fd);
    }

    uint32_t connectionId = CalTcpConnectionId(fd);
    if (WrapperAddTcpConnInfo(option, result, connectionId, requestId, fd, *statistics) != SOFTBUS_OK) {
        ConnShutdownSocket(fd);
        result->OnConnectFailed(requestId, SOFTBUS_ERR);
        DfxRecordTcpConnectFail(DEFAULT_PID, (ConnectOption *)option, NULL, statistics, error);
        SoftBusFree(statistics);
        return SOFTBUS_ERR;
    }
    if (AddTrigger((ListenerModule)(option->socketOption.moduleId), fd, WRITE_TRIGGER) != SOFTBUS_OK) {
        DelTcpConnNode(connectionId);
        ConnShutdownSocket(fd);
        result->OnConnectFailed(requestId, SOFTBUS_ERR);
        DfxRecordTcpConnectFail(DEFAULT_PID, (ConnectOption *)option, NULL, statistics, error);
        SoftBusFree(statistics);
        return SOFTBUS_ERR;
    }
    SoftBusFree(statistics);
    CONN_LOGI(CONN_COMMON, "tcp connect add write trigger ok");
    return SOFTBUS_OK;
}

int32_t TcpDisconnectDevice(uint32_t connectionId)
{
    ConnectionInfo info;
    if (TcpGetConnectionInfo(connectionId, &info) != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "tcp get connection info failed");
        return SOFTBUS_ERR;
    }
    DelTcpConnInfo(connectionId, UNUSE_BUTT, -1);
    return SOFTBUS_OK;
}

int32_t TcpDisconnectDeviceNow(const ConnectOption *option)
{
    if (g_tcpConnInfoList == NULL || option == NULL) {
        CONN_LOGE(CONN_COMMON, "tcp connection info list is null or option is null");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
        CONN_LOGE(CONN_COMMON, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TcpConnInfoNode *item = NULL;
    TcpConnInfoNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpConnInfoList->list, TcpConnInfoNode, node)
    {
        if (option->socketOption.protocol == item->info.socketInfo.protocol &&
            strcmp(option->socketOption.addr, item->info.socketInfo.addr) == 0) {
            (void)DelTrigger((ListenerModule)(item->info.socketInfo.moduleId), item->info.socketInfo.fd, RW_TRIGGER);
            ConnShutdownSocket(item->info.socketInfo.fd);
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

int32_t TcpPostBytes(
    uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq)
{
    (void)pid;
    (void)module;
    (void)seq;
    TcpConnInfoNode *item = NULL;
    if (data == NULL || len == 0) {
        CONN_LOGE(CONN_COMMON, "data is null or len is 0");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_tcpConnInfoList == NULL) {
        CONN_LOGE(CONN_COMMON, "tcp connection list is null");
        SoftBusFree((void*)data);
        return SOFTBUS_ERR;
    }
    int32_t fd = -1;
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
        CONN_LOGE(CONN_COMMON, "lock failed");
        SoftBusFree((void*)data);
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (item->connectionId == connectionId) {
            fd = item->info.socketInfo.fd;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
    if (fd == -1) {
        SoftBusFree((void*)data);
        CONN_LOGE(CONN_COMMON, "TcpPostBytes failed, connectionId:%08x not found.", connectionId);
        return SOFTBUS_ERR;
    }
    uint32_t bytes = ConnSendSocketData(fd, (const char *)data, len, flag);
    SoftBusFree(data);
    if (bytes != len) {
        CONN_LOGE(CONN_COMMON, "socket send data is mismatched");
        return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TcpGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    if (g_tcpConnInfoList == NULL) {
        CONN_LOGE(CONN_COMMON, "tcp connection list is null");
        return SOFTBUS_ERR;
    }
    if (info == NULL) {
        CONN_LOGW(CONN_COMMON, "info is NULL.");
        return SOFTBUS_INVALID_PARAM;
    }
    TcpConnInfoNode *item = NULL;
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != 0) {
        CONN_LOGE(CONN_COMMON, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_tcpConnInfoList->list, TcpConnInfoNode, node) {
        if (item->connectionId == connectionId) {
            int32_t ret = memcpy_s(info, sizeof(ConnectionInfo), &item->info, sizeof(ConnectionInfo));
            (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
            if (ret != EOK) {
                CONN_LOGE(CONN_COMMON, "copy connection info failed");
                return SOFTBUS_MEM_ERR;
            }
            return SOFTBUS_OK;
        }
    }
    info->isAvailable = false;
    (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
    CONN_LOGE(CONN_COMMON, "ConnectionId:%08x is not exists.", connectionId);
    return SOFTBUS_ERR;
}

int32_t TcpStartListening(const LocalListenerInfo *info)
{
    if (info == NULL || (info->type != CONNECT_TCP && info->type != CONNECT_P2P)) {
        return SOFTBUS_INVALID_PARAM;
    }
    static SoftbusBaseListener listener = {
        .onConnectEvent = TcpOnConnectEvent,
        .onDataEvent = TcpOnDataEvent
    };
    return StartBaseListener(info, &listener);
}

int32_t TcpStopListening(const LocalListenerInfo *info)
{
    if (info == NULL) {
        CONN_LOGW(CONN_COMMON, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }

    ListenerModule moduleId = info->socketOption.moduleId;
    int32_t ret = StopBaseListener(moduleId);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "stop listener failed");
        return ret;
    }
    DelAllConnInfo(moduleId);
    return SOFTBUS_OK;
}

static int32_t InitProperty(void)
{
    g_tcpMaxConnNum = INVALID_DATA;
    g_tcpTimeOut = INVALID_DATA;
    g_tcpMaxLen = 0;
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_TCP_MAX_CONN_NUM,
        (unsigned char*)&g_tcpMaxConnNum, sizeof(g_tcpMaxConnNum)) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "get tcp MaxConnNum fail");
    }
    CONN_LOGI(CONN_INIT, "tcp MaxConnNum is %d", g_tcpMaxConnNum);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_TCP_MAX_LENGTH,
        (unsigned char*)&g_tcpMaxLen, sizeof(g_tcpMaxLen)) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "get tcp MaxLen fail");
    }
    CONN_LOGI(CONN_INIT, "tcp MaxLen is %d", g_tcpMaxLen);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_TCP_TIME_OUT,
        (unsigned char*)&g_tcpTimeOut, sizeof(g_tcpTimeOut)) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "get tcp TimeOut fail");
    }
    CONN_LOGI(CONN_INIT, "tcp TimeOut is %d", g_tcpTimeOut);
    if (g_tcpMaxConnNum == INVALID_DATA || g_tcpTimeOut == INVALID_DATA || g_tcpMaxLen == 0) {
        CONN_LOGE(CONN_INIT, "Cannot get brBuffSize");
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
    g_tcpInterface.UpdateConnection = NULL;
    g_tcpInterface.PreventConnection = NULL;
}

ConnectFuncInterface *ConnInitTcp(const ConnectCallback *callback)
{
    if (callback == NULL) {
        CONN_LOGW(CONN_INIT, "ConnectCallback is NULL.");
        return NULL;
    }
    if (InitProperty() != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "Can not InitProperty");
        return NULL;
    }
    InitTcpInterface();
    g_tcpConnCallback = callback;

    if (g_tcpConnInfoList == NULL) {
        g_tcpConnInfoList = CreateSoftBusList();
        if (g_tcpConnInfoList == NULL) {
            CONN_LOGE(CONN_INIT, "Create tcpConnInfoList failed.");
            return NULL;
        }
        g_tcpConnInfoList->cnt = 0;
    }
    SoftBusRegConnVarDump(TCP_CONNECT_INFO, &TcpConnectInfoDump);
    return &g_tcpInterface;
}

static int TcpConnectInfoDump(int fd)
{
    char addr[MAX_SOCKET_ADDR_LEN] = {0};
    if (SoftBusMutexLock(&g_tcpConnInfoList->lock) != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ListNode *item = NULL;
    SOFTBUS_DPRINTF(fd, "\n-----------------TcpConnect Info-------------------\n");
    LIST_FOR_EACH(item, &g_tcpConnInfoList->list) {
        TcpConnInfoNode *itemNode = LIST_ENTRY(item, TcpConnInfoNode, node);
        SOFTBUS_DPRINTF(fd, "Tcp Connect connectionId          : %u\n", itemNode->connectionId);
        SOFTBUS_DPRINTF(fd, "Connection Info isAvailable       : %d\n", itemNode->info.isAvailable);
        SOFTBUS_DPRINTF(fd, "Connection Info isServer          : %d\n", itemNode->info.isServer);
        SOFTBUS_DPRINTF(fd, "Connection Info type              : %d\n", itemNode->info.type);
        SOFTBUS_DPRINTF(fd, "SocketInfo                        :\n");
        DataMasking(itemNode->info.socketInfo.addr, MAX_SOCKET_ADDR_LEN, MAC_DELIMITER, addr);
        SOFTBUS_DPRINTF(fd, "SocketInfo addr                   : %s\n", addr);
        SOFTBUS_DPRINTF(fd, "SocketInfo protocol               : %"PRIu64"\n", itemNode->info.socketInfo.protocol);
        SOFTBUS_DPRINTF(fd, "SocketInfo port                   : %d\n", itemNode->info.socketInfo.port);
        SOFTBUS_DPRINTF(fd, "SocketInfo fd                     : %d\n", itemNode->info.socketInfo.fd);
        SOFTBUS_DPRINTF(fd, "SocketInfo moduleId               : %d\n", itemNode->info.socketInfo.moduleId);
        SOFTBUS_DPRINTF(fd, "Connection Info requestId         : %d\n", itemNode->requestId);
    }
    (void)SoftBusMutexUnlock(&g_tcpConnInfoList->lock);
    return SOFTBUS_OK;
}