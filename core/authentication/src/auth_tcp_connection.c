/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "auth_tcp_connection.h"

#include <securec.h>

#include "auth_channel.h"
#include "auth_common.h"
#include "bus_center_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_base_listener.h"
#include "softbus_socket.h"

#define MAGIC_NUMBER  0xBABEFACE
#define AUTH_PKT_HEAD_LEN 24
#define AUTH_KEEP_ALIVE_TIME_INTERVAL (10 * 60)
#define AUTH_SOCKET_MAX_DATA_LEN (64 * 1024)

typedef struct {
    int32_t magic;
    int32_t module;
    int64_t seq;
    int32_t flag;
    uint32_t len;
} SocketPktHead;

typedef struct {
    int32_t module;
    AuthChannelListener listener;
} InnerChannelListener;

static InnerChannelListener g_listener[] = {
    {
        .module = MODULE_AUTH_CHANNEL,
        .listener = { NULL, NULL },
    },
    {
        .module = MODULE_AUTH_MSG,
        .listener = { NULL, NULL },
    },
};

static SocketCallback g_callback = {NULL, NULL, NULL};

static void NotifyChannelDisconnected(int32_t channelId);
static void NotifyChannelDataReceived(int32_t channelId, const SocketPktHead *head, const uint8_t *data);

static uint32_t GetSocketPktSize(uint32_t len)
{
    return AUTH_PKT_HEAD_LEN + len;
}

static int32_t PackSocketPkt(const SocketPktHead *pktHead, const uint8_t *data,
    uint8_t *buf, uint32_t size)
{
    if (size < GetSocketPktSize(pktHead->len)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SocketPkt: buffer not enough.");
        return SOFTBUS_NO_ENOUGH_DATA;
    }
    uint32_t offset = 0;
    *(uint32_t *)buf = SoftBusHtoLl((uint32_t)pktHead->magic);
    offset += sizeof(uint32_t);
    *(uint32_t *)(buf + offset) = SoftBusHtoLl((uint32_t)pktHead->module);
    offset += sizeof(uint32_t);
    *(uint64_t *)(buf + offset) = SoftBusHtoLll((uint64_t)pktHead->seq);
    offset += sizeof(uint64_t);
    *(uint32_t *)(buf + offset) = SoftBusHtoLl((uint32_t)pktHead->flag);
    offset += sizeof(uint32_t);
    *(uint32_t *)(buf + offset) = SoftBusHtoLl(pktHead->len);
    offset += sizeof(uint32_t);
    if (memcpy_s(buf + offset, size - offset, data, pktHead->len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SocketPkt: pack fail.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UnpackSocketPkt(const uint8_t *data, uint32_t len, SocketPktHead *head)
{
    if (len < GetSocketPktSize(0)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SocketPkt: head not enough.");
        return SOFTBUS_NO_ENOUGH_DATA;
    }
    uint32_t offset = 0;
    head->magic = (int32_t)SoftBusLtoHl(*(uint32_t *)data);
    offset += sizeof(uint32_t);
    head->module = (int32_t)SoftBusLtoHl(*(uint32_t *)(data + offset));
    offset += sizeof(uint32_t);
    head->seq = (int64_t)SoftBusLtoHll(*(uint64_t *)(data + offset));
    offset += sizeof(uint64_t);
    head->flag = (int32_t)SoftBusLtoHl(*(uint32_t *)(data + offset));
    offset += sizeof(uint32_t);
    head->len = SoftBusLtoHl(*(uint32_t *)(data + offset));
    return SOFTBUS_OK;
}

static void NotifyConnected(int32_t fd, bool isClient)
{
    if (g_callback.onConnected != NULL) {
        g_callback.onConnected(fd, isClient);
    }
}

static void NotifyDisconnected(int32_t fd)
{
    if (g_callback.onDisconnected != NULL) {
        g_callback.onDisconnected(fd);
    }
    NotifyChannelDisconnected(fd);
}

static uint32_t ModuleToDataType(int32_t module)
{
    switch (module) {
        case MODULE_TRUST_ENGINE:
            return DATA_TYPE_DEVICE_ID;
        case MODULE_AUTH_SDK:
            return DATA_TYPE_AUTH;
        case MODULE_AUTH_CONNECTION:
            return DATA_TYPE_DEVICE_INFO;
        default:
            break;
    }
    return DATA_TYPE_CONNECTION;
}

static void NotifyDataReceived(int32_t fd, const SocketPktHead *pktHead, const uint8_t *data)
{
    if (pktHead->module == MODULE_AUTH_CHANNEL || pktHead->module == MODULE_AUTH_MSG) {
        NotifyChannelDataReceived(fd, pktHead, data);
        return;
    }
    AuthDataHead head = {
        .dataType = ModuleToDataType(pktHead->module),
        .module = pktHead->module,
        .seq = pktHead->seq,
        .flag = pktHead->flag,
        .len = pktHead->len,
    };
    if (g_callback.onDataReceived != NULL) {
        g_callback.onDataReceived(fd, &head, data);
    }
}

static int32_t RecvPacketHead(int32_t fd, SocketPktHead *head)
{
    uint8_t buf[AUTH_PKT_HEAD_LEN] = {0};
    ssize_t len = ConnRecvSocketData(fd, (char *)&buf[0], sizeof(buf), 0);
    if (len < AUTH_PKT_HEAD_LEN) {
        if (len < 0) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "recv head fail(=%d).", ConnGetSocketError(fd));
            (void)DelTrigger(AUTH, fd, READ_TRIGGER);
            ConnShutdownSocket(fd);
            NotifyDisconnected(fd);
        }
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "head not enough, len=%d, abandon it.", len);
        return SOFTBUS_ERR;
    }
    return UnpackSocketPkt(buf, len, head);
}

static uint8_t *RecvPacketData(int32_t fd, uint32_t len)
{
    uint8_t *data = (uint8_t *)SoftBusMalloc(len);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "malloc data buf fail.");
        return NULL;
    }
    uint32_t offset = 0;
    while (offset < len) {
        ssize_t recvLen = ConnRecvSocketData(fd, (char *)(data + offset), (size_t)(len - offset), 0);
        if (recvLen < 0) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "recv data fail(=%d).", ConnGetSocketError(fd));
            SoftBusFree(data);
            return NULL;
        }
        offset += (uint32_t)recvLen;
    }
    return data;
}

static int32_t ProcessSocketOutEvent(int32_t fd)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "socket client connect succ: fd=%d.", fd);
    (void)DelTrigger(AUTH, fd, WRITE_TRIGGER);
    if (AddTrigger(AUTH, fd, READ_TRIGGER) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AddTrigger fail.");
        goto FAIL;
    }
    if (ConnToggleNonBlockMode(fd, false) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "set block mode fail.");
        goto FAIL;
    }
    NotifyConnected(fd, true);
    return SOFTBUS_OK;

FAIL:
    (void)DelTrigger(AUTH, fd, READ_TRIGGER);
    ConnShutdownSocket(fd);
    NotifyDisconnected(fd);
    return SOFTBUS_ERR;
}

static int32_t ProcessSocketInEvent(int32_t fd)
{
    SocketPktHead head = {0};
    if (RecvPacketHead(fd, &head) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "RecvSocketData: fd=%d, module=%d, seq=%" PRId64 ", flag=%d, len=%u.",
        fd, head.module, head.seq, head.flag, head.len);
    if (head.len == 0 || head.len > AUTH_SOCKET_MAX_DATA_LEN) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "data is out of size, abandon it.");
        return SOFTBUS_ERR;
    }
    if (head.magic != (int32_t)MAGIC_NUMBER) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "magic number not match.");
        return SOFTBUS_ERR;
    }
    uint8_t *data = RecvPacketData(fd, head.len);
    if (data == NULL) {
        return SOFTBUS_ERR;
    }
    NotifyDataReceived(fd, &head, data);
    SoftBusFree(data);
    return SOFTBUS_OK;
}

static int32_t OnConnectEvent(ListenerModule module, int32_t events,
    int32_t cfd, const ConnectOption *clientAddr)
{
    (void)module;
    (void)clientAddr;
    if (events == SOFTBUS_SOCKET_EXCEPTION) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "exception occurred, fd=%d.", cfd);
        return SOFTBUS_ERR;
    }
    if (cfd < 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    if (ConnSetTcpKeepAlive(cfd, AUTH_KEEP_ALIVE_TIME_INTERVAL) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "set keepalive fail!");
        ConnShutdownSocket(cfd);
        return SOFTBUS_ERR;
    }
    if (AddTrigger(AUTH, cfd, READ_TRIGGER) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AddTrigger fail.");
        ConnShutdownSocket(cfd);
        return SOFTBUS_ERR;
    }
    NotifyConnected(cfd, false);
    return SOFTBUS_OK;
}

static int32_t OnDataEvent(ListenerModule module, int32_t events, int32_t fd)
{
    (void)module;
    if (events == SOFTBUS_SOCKET_OUT) {
        return ProcessSocketOutEvent(fd);
    } else if (events == SOFTBUS_SOCKET_IN) {
        return ProcessSocketInEvent(fd);
    }
    return SOFTBUS_ERR;
}

int32_t SetSocketCallback(const SocketCallback *cb)
{
    CHECK_NULL_PTR_RETURN_VALUE(cb, SOFTBUS_INVALID_PARAM);
    if (memcpy_s(&g_callback, sizeof(SocketCallback), cb, sizeof(SocketCallback)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "set SocketCallback fail.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

void UnsetSocketCallback(void)
{
    (void)memset_s(&g_callback, sizeof(SocketCallback), 0, sizeof(SocketCallback));
}

int32_t StartSocketListening(const char *ip, int32_t port)
{
    CHECK_NULL_PTR_RETURN_VALUE(ip, SOFTBUS_INVALID_PARAM);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "start socket listening.");
    LocalListenerInfo info = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "",
            .port = port,
            .moduleId = AUTH,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    if (strcpy_s(info.socketOption.addr, sizeof(info.socketOption.addr), ip) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strcpy_s ip fail.");
        return SOFTBUS_MEM_ERR;
    }
    SoftbusBaseListener listener = {
        .onConnectEvent = OnConnectEvent,
        .onDataEvent = OnDataEvent,
    };
    if (SetSoftbusBaseListener(AUTH, &listener) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "set listener fail.");
        return SOFTBUS_ERR;
    }
    port = StartBaseListener(&info);
    if (port <= 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "StartBaseListener fail(=%d).", port);
        return SOFTBUS_ERR;
    }
    return port;
}

void StopSocketListening(void)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "stop socket listening.");
    if (StopBaseListener(AUTH) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "StopBaseListener fail.");
    }
}

int32_t SocketConnectDevice(const char *ip, int32_t port, bool isBlockMode)
{
    char localIp[MAX_ADDR_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, MAX_ADDR_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get local ip fail.");
        return AUTH_INVALID_FD;
    }
    ConnectOption option = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "",
            .port = port,
            .moduleId = AUTH,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    if (strcpy_s(option.socketOption.addr, sizeof(option.socketOption.addr), ip) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy remote ip fail.");
        return AUTH_INVALID_FD;
    }
    int32_t fd = ConnOpenClientSocket(&option, localIp, !isBlockMode);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "ConnOpenClientSocket fail.");
        return AUTH_INVALID_FD;
    }
    TriggerType triggerMode = isBlockMode ? READ_TRIGGER : WRITE_TRIGGER;
    if (AddTrigger(AUTH, fd, triggerMode) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AddTrigger fail.");
        ConnShutdownSocket(fd);
        return AUTH_INVALID_FD;
    }
    if (ConnSetTcpKeepAlive(fd, AUTH_KEEP_ALIVE_TIME_INTERVAL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "set tcp keep alive fail.");
        (void)DelTrigger(AUTH, fd, triggerMode);
        ConnShutdownSocket(fd);
        return AUTH_INVALID_FD;
    }
    return fd;
}

void SocketDisconnectDevice(int32_t fd)
{
    if (fd < 0) {
        return;
    }
    (void)DelTrigger(AUTH, fd, RW_TRIGGER);
    ConnShutdownSocket(fd);
}

int32_t SocketPostBytes(int32_t fd, const AuthDataHead *head, const uint8_t *data)
{
    CHECK_NULL_PTR_RETURN_VALUE(head, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(data, SOFTBUS_INVALID_PARAM);
    uint32_t size = GetSocketPktSize(head->len);
    uint8_t *buf = (uint8_t *)SoftBusCalloc(size);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "malloc pkt err.");
        return SOFTBUS_ERR;
    }
    SocketPktHead pktHead = {
        .magic = MAGIC_NUMBER,
        .module = head->module,
        .seq = head->seq,
        .flag = head->flag,
        .len = head->len,
    };
    if (PackSocketPkt(&pktHead, data, buf, size) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "pack socket pkt fail.");
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "SocketPostBytes: fd=%d, module=%d, seq=%"PRId64", flag=%d, len=%u.",
        fd, pktHead.module, pktHead.seq, pktHead.flag, pktHead.len);
    ssize_t ret = ConnSendSocketData(fd, (const char *)buf, (size_t)size, 0);
    SoftBusFree(buf);
    if (ret != (ssize_t)size) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "ConnSendSocketData fail(=%d).", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SocketGetConnInfo(int32_t fd, AuthConnInfo *connInfo, bool *isServer)
{
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(isServer, SOFTBUS_INVALID_PARAM);
    SocketAddr socket;
    if (ConnGetPeerSocketAddr(fd, &socket) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "ConnGetPeerSocketAddr fail, fd=%d.", fd);
        return SOFTBUS_ERR;
    }
    int32_t localPort = ConnGetLocalSocketPort(fd);
    if (localPort <= 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "ConnGetLocalSocketPort fail, fd=%d.", fd);
        return SOFTBUS_ERR;
    }
    connInfo->type = AUTH_LINK_TYPE_WIFI;
    if (strcpy_s(connInfo->info.ipInfo.ip, sizeof(connInfo->info.ipInfo.ip), socket.addr) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy ip fail, fd=%d.", fd);
        return SOFTBUS_MEM_ERR;
    }
    connInfo->info.ipInfo.port = socket.port;
    int32_t serverPort = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &serverPort) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get local auth port fail.");
        return SOFTBUS_ERR;
    }
    *isServer = (serverPort != localPort);
    return SOFTBUS_OK;
}

/* Auth Channel */
static void NotifyChannelDataReceived(int32_t channelId, const SocketPktHead *head, const uint8_t *data)
{
    uint32_t i;
    AuthChannelListener *listener = NULL;
    for (i = 0; i < sizeof(g_listener) / sizeof(InnerChannelListener); i++) {
        if (g_listener[i].module == head->module) {
            listener = &g_listener[i].listener;
            break;
        }
    }
    if (listener == NULL || listener->onDataReceived == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthChannelListener not set.");
        return;
    }

    AuthChannelData channelData = {
        .module = head->module,
        .seq = head->seq,
        .flag = head->flag,
        .len = head->len,
        .data = data,
    };
    listener->onDataReceived(channelId, &channelData);
}

static void NotifyChannelDisconnected(int32_t channelId)
{
    uint32_t i;
    for (i = 0; i < sizeof(g_listener) / sizeof(InnerChannelListener); i++) {
        if (g_listener[i].listener.onDisconnected != NULL) {
            g_listener[i].listener.onDisconnected(channelId);
        }
    }
}

int32_t RegAuthChannelListener(int32_t module, const AuthChannelListener *listener)
{
    if (listener == NULL || listener->onDataReceived == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthChannel: invalid listener.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t i;
    for (i = 0; i < sizeof(g_listener) / sizeof(InnerChannelListener); i++) {
        if (g_listener[i].module == module) {
            g_listener[i].listener.onDataReceived = listener->onDataReceived;
            g_listener[i].listener.onDisconnected = listener->onDisconnected;
            return SOFTBUS_OK;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthChannel: unknown module(=%d).", module);
    return SOFTBUS_ERR;
}

void UnregAuthChannelListener(int32_t module)
{
    uint32_t i;
    for (i = 0; i < sizeof(g_listener) / sizeof(InnerChannelListener); i++) {
        if (g_listener[i].module == module) {
            g_listener[i].listener.onDataReceived = NULL;
            g_listener[i].listener.onDisconnected = NULL;
            return;
        }
    }
}

int32_t AuthOpenChannel(const char *ip, int32_t port)
{
    if (ip == NULL || port <= 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthChannel: invalid param.");
        return INVALID_CHANNEL_ID;
    }
    int32_t fd = SocketConnectDevice(ip, port, true);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthChannel: connect fail.");
        return INVALID_CHANNEL_ID;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "AuthChannel: open auth channel succ, channelId=%d.", fd);
    return fd;
}

void AuthCloseChannel(int32_t channelId)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "AuthChannel: close auth channel, id=%d.", channelId);
    SocketDisconnectDevice(channelId);
}

int32_t AuthPostChannelData(int32_t channelId, const AuthChannelData *data)
{
    if (channelId < 0 || data == NULL || data->data == NULL || data->len == 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthChannel: invalid param, channelId=%d.", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    AuthDataHead head = {
        .dataType = DATA_TYPE_CONNECTION,
        .module = data->module,
        .seq = data->seq,
        .flag = data->flag,
        .len = data->len,
    };
    return SocketPostBytes(channelId, &head, data->data);
}
