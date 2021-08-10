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

#include "trans_tcp_direct_listener.h"

#include <arpa/inet.h>
#include <securec.h>
#include <unistd.h>

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_crypto.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_message_open_channel.h"
#include "softbus_tcp_socket.h"
#include "trans_tcp_direct_message.h"

static SoftbusBaseListener *g_sessionListener = NULL;

static int32_t StartVerifySession(SessionConn *conn)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "StartVerifySession");
    uint64_t seq = TransTdcGetNewSeqId(conn->serverSide);
    if (GenerateSessionKey(conn->appInfo.sessionKey, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Generate SessionKey failed");
        return SOFTBUS_ERR;
    }
    char *bytes = PackRequest(&conn->appInfo);
    if (bytes == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Pack Request failed");
        return SOFTBUS_ERR;
    }

    uint32_t dataLen = strlen(bytes) + OVERHEAD_LEN + MESSAGE_INDEX_SIZE;
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = seq,
        .flags = FLAG_REQUEST,
        .dataLen = dataLen,
    };

    if (TransTdcPostBytes(conn->channelId, &packetHead, bytes) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransTdc post bytes failed");
        SoftBusFree(bytes);
        return SOFTBUS_ERR;
    }
    SoftBusFree(bytes);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "StartVerifySession ok");

    return SOFTBUS_OK;
}

static int32_t GetUuidFromAuth(const char *ip, char *uuid, uint32_t len)
{
    if (ip == NULL || uuid == NULL) {
        return SOFTBUS_ERR;
    }
    ConnectOption option = {0};
    option.type = CONNECT_TCP;
    if (strcpy_s(option.info.ipOption.ip, IP_LEN, ip) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s peer ip err.");
        return SOFTBUS_MEM_ERR;
    }
    if (AuthGetUuidByOption(&option, uuid, len) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get uuid fail.");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t OnConnectEvent(int events, int cfd, const char *ip)
{
    if (events == SOFTBUS_SOCKET_EXCEPTION) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Exception occurred");
        return SOFTBUS_ERR;
    }
    if (cfd < 0 || ip == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param, cfd = %d", cfd);
        return SOFTBUS_INVALID_PARAM;
    }
    SessionConn *item = (SessionConn *)SoftBusMalloc(sizeof(SessionConn));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Malloc error occurred");
        return SOFTBUS_MALLOC_ERR;
    }
    item->appInfo.myData.apiVersion = API_V2;
    item->appInfo.fd = cfd;
    item->serverSide = true;
    item->channelId = GenerateTdcChannelId();
    item->status = TCP_DIRECT_CHANNEL_STATUS_CONNECTING;
    item->timeout = 0;
    item->dataBuffer.w = item->dataBuffer.data;

    if (LnnGetLocalStrInfo(STRING_KEY_UUID, item->appInfo.myData.deviceId,
        sizeof(item->appInfo.myData.deviceId)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get local deviceId failed");
        SoftBusFree(item);
        return SOFTBUS_ERR;
    }

    if (GetUuidFromAuth(ip, item->appInfo.peerData.deviceId, DEVICE_ID_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusFree(item);
        return SOFTBUS_ERR;
    }

    if (memcpy_s(item->appInfo.peerData.ip, IP_LEN, ip, strlen(ip) + 1) != EOK) {
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }

    char *authState = "";
    if (memcpy_s(item->appInfo.myData.authState, AUTH_STATE_SIZE_MAX, "", strlen(authState) + 1) != EOK) {
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }

    if (TransTdcAddSessionConn(item) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransTdcAddSessionConn failed");
        SoftBusFree(item);
        return SOFTBUS_ERR;
    }
    if (AddTrigger(DIRECT_CHANNEL_SERVER, cfd, READ_TRIGGER) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add trigger failed, delete session conn.");
        TransTdcDelSessionConn(item);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t OnDataEvent(int events, int fd)
{
    SessionConn *conn = GetTdcInfoByFd(fd);
    if (conn == NULL || conn->appInfo.fd != fd) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fd[%d] is not exist tdc info.", fd);
        return SOFTBUS_ERR;
    }
    int32_t ret = SOFTBUS_ERR;
    if (events == SOFTBUS_SOCKET_IN) {
        ret = TransTdcProcessPacket(conn->channelId);
        if (ret != SOFTBUS_DATA_NOT_ENOUGH) {
            DelTrigger(DIRECT_CHANNEL_SERVER, fd, READ_TRIGGER);
            CloseTcpFd(fd);
            if (ret != SOFTBUS_OK) {
                NotifyChannelOpenFailed(conn->channelId);
            }
            TransTdcDelSessionConn(conn);
        }
    } else if (events == SOFTBUS_SOCKET_OUT) {
        if (conn->serverSide == true) {
            return ret;
        }
        DelTrigger(DIRECT_CHANNEL_SERVER, fd, WRITE_TRIGGER);
        AddTrigger(DIRECT_CHANNEL_SERVER, fd, READ_TRIGGER);
        ret = StartVerifySession(conn);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "start verify session fail.");
            DelTrigger(DIRECT_CHANNEL_SERVER, fd, READ_TRIGGER);
            CloseTcpFd(fd);
            NotifyChannelOpenFailed(conn->channelId);
            TransTdcDelSessionConn(conn);
        }
    } else if (events == SOFTBUS_SOCKET_EXCEPTION) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "exception occurred.");
        DelTrigger(DIRECT_CHANNEL_SERVER, fd, EXCEPT_TRIGGER);
        CloseTcpFd(fd);
        TransTdcDelSessionConn(conn);
    }
    return ret;
}

int32_t TransTdcStartSessionListener(const char *ip, const int port)
{
    if (ip == NULL || port < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid para.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_sessionListener == NULL) {
        g_sessionListener = (SoftbusBaseListener *)SoftBusCalloc(sizeof(SoftbusBaseListener));
        if (g_sessionListener == NULL) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Failed to create listener");
            return SOFTBUS_ERR;
        }
    }

    g_sessionListener->onConnectEvent = OnConnectEvent;
    g_sessionListener->onDataEvent = OnDataEvent;

    int32_t ret = SetSoftbusBaseListener(DIRECT_CHANNEL_SERVER, g_sessionListener);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Set BaseListener Failed.");
        SoftBusFree(g_sessionListener);
        g_sessionListener = NULL;
        return ret;
    }

    if (GetTdcInfoList() == NULL) {
        SetTdcInfoList(CreateSoftBusList());
        if (GetTdcInfoList() == NULL) {
            SoftBusFree(g_sessionListener);
            g_sessionListener = NULL;
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetTdcInfoList is null.");
            return SOFTBUS_MALLOC_ERR;
        }
    }

    int serverPort = StartBaseListener(DIRECT_CHANNEL_SERVER, ip, port, SERVER_MODE);
    return serverPort;
}

int32_t TransTdcStopSessionListener(void)
{
    int32_t ret = SetSoftbusBaseListener(DIRECT_CHANNEL_SERVER, g_sessionListener);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Set BaseListener Failed.");
        return ret;
    }

    if (g_sessionListener != NULL) {
        SoftBusFree(g_sessionListener);
        g_sessionListener = NULL;
    }

    if (GetTdcInfoList() != NULL) {
        DestroySoftBusList(GetTdcInfoList());
        SetTdcInfoList(NULL);
    }

    ret = StopBaseListener(DIRECT_CHANNEL_SERVER);
    return ret;
}

SoftbusBaseListener *TransTdcGetSessionListener(void)
{
    return g_sessionListener;
}

