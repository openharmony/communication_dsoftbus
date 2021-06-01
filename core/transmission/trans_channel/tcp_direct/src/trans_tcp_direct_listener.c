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
#include "softbus_base_listener.h"
#include "softbus_crypto.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_message_open_channel.h"
#include "softbus_tcp_socket.h"
#include "trans_tcp_direct_message.h"

static SoftbusBaseListener *g_sessionListener = NULL;

static int32_t StartVerifySession(SessionConn *conn)
{
    LOG_INFO("StartVerifySession");
    if (conn->authStarted == true) {
        return SOFTBUS_OK;
    }

    uint64_t seq = TransTdcGetNewSeqId(conn->serverSide);
    if (GenerateSessionKey(conn->appInfo.sessionKey, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        LOG_ERR("Generate SessionKey failed");
        return SOFTBUS_ERR;
    }
    char *bytes = PackRequest(&conn->appInfo);
    if (bytes == NULL) {
        LOG_ERR("Pack Request failed");
        return SOFTBUS_ERR;
    }
    uint32_t flags = 0;
    uint32_t dataLen = strlen(bytes) + OVERHEAD_LEN + MESSAGE_INDEX_SIZE;
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = seq,
        .flags = flags,
        .dataLen = dataLen,
    };

    if (TransTdcPostBytes(conn->channelId, &packetHead, bytes) != SOFTBUS_OK) {
        LOG_ERR("TransTdc post bytes failed");
        SoftBusFree(bytes);
        return SOFTBUS_ERR;
    }
    SoftBusFree(bytes);
    LOG_INFO("StartVerifySession ok");

    conn->authStarted = true;
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
        LOG_ERR("strcpy_s peer ip err.");
        return SOFTBUS_MEM_ERR;
    }
    if (AuthGetUuidByOption(&option, uuid, len) != SOFTBUS_OK) {
        LOG_ERR("get uuid fail.");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t OnConnectEvent(int events, int cfd, const char *ip)
{
    if (events == SOFTBUS_SOCKET_EXCEPTION) {
        LOG_ERR("Exception occurred");
        return SOFTBUS_ERR;
    }
    if (cfd < 0 || ip == NULL) {
        LOG_ERR("invalid param, cfd = %d", cfd);
        return SOFTBUS_INVALID_PARAM;
    }
    SessionConn *item = (SessionConn *)SoftBusMalloc(sizeof(SessionConn));
    if (item == NULL) {
        LOG_ERR("Malloc error occurred");
        return SOFTBUS_MALLOC_ERR;
    }
    item->appInfo.myData.apiVersion = API_V2;
    item->appInfo.fd = cfd;
    item->serverSide = true;
    item->channelId = cfd;
    item->status = TCP_DIRECT_CHANNEL_STATUS_CONNECTING;
    item->timeout = 0;

    if (LnnGetLocalStrInfo(STRING_KEY_UUID, item->appInfo.myData.deviceId,
        sizeof(item->appInfo.myData.deviceId)) != 0) {
        LOG_ERR("get local deviceId failed");
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

    if (TransTdcAddSessionConn(item, RW_TRIGGER) != SOFTBUS_OK) {
        LOG_ERR("TransTdcAddSessionConn failed");
        TransTdcCloseSessionConn(item->channelId);
        SoftBusFree(item);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t OnDataEvent(int events, int fd)
{
    SessionConn *item = GetTdcInfoByFd(fd);
    if (item == NULL || item->appInfo.fd != fd) {
        LOG_ERR("fd[%d] is not exist tdc info", fd);
        return SOFTBUS_ERR;
    }

    if (events == SOFTBUS_SOCKET_EXCEPTION) {
        LOG_ERR("Exception occurred");
        TransTdcCloseSessionConn(item->channelId);
        if (item->serverSide == true || item->openChannelFinished == true) {
            SoftBusFree(item);
        }
        return SOFTBUS_ERR;
    }
    if (events == SOFTBUS_SOCKET_OUT && item->serverSide == false) {
        if (StartVerifySession(item) != SOFTBUS_OK) {
            TransTdcCloseSessionConn(item->channelId);
            if (item->serverSide == true || item->openChannelFinished == true) {
                SoftBusFree(item);
            }
            return SOFTBUS_ERR;
        }
    }
    if (TransTdcProcessPacket(item->channelId) != SOFTBUS_OK) {
        LOG_ERR("ProcessPacket err");
        TransTdcCloseSessionConn(item->channelId);
        if (item->serverSide == true || item->openChannelFinished == true) {
            SoftBusFree(item);
        }
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransTdcStartSessionListener(const char *ip, const int port)
{
    if (ip == NULL || port < 0) {
        LOG_ERR("Invalid para.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_sessionListener == NULL) {
        g_sessionListener = (SoftbusBaseListener *)SoftBusCalloc(sizeof(SoftbusBaseListener));
        if (g_sessionListener == NULL) {
            LOG_ERR("Failed to create listener");
            return SOFTBUS_ERR;
        }
    }

    g_sessionListener->onConnectEvent = OnConnectEvent;
    g_sessionListener->onDataEvent = OnDataEvent;

    int32_t ret = SetSoftbusBaseListener(DIRECT_CHANNEL_SERVER, g_sessionListener);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("Set BaseListener Failed.");
        SoftBusFree(g_sessionListener);
        g_sessionListener = NULL;
        return ret;
    }

    if (GetTdcInfoList() == NULL) {
        SetTdcInfoList(CreateSoftBusList());
        if (GetTdcInfoList() == NULL) {
            SoftBusFree(g_sessionListener);
            g_sessionListener = NULL;
            LOG_ERR("GetTdcInfoList is null.");
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
        LOG_ERR("Set BaseListener Failed.");
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

