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
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_message_open_channel.h"
#include "softbus_tcp_socket.h"
#include "trans_tcp_direct_message.h"

static SoftbusBaseListener *g_sessionListener = NULL;

static int32_t StartVerifySession(SessionConn *conn)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "StartVerifySession");
    uint64_t seq = TransTdcGetNewSeqId();
    if (SoftBusGenerateSessionKey(conn->appInfo.sessionKey, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Generate SessionKey failed");
        return SOFTBUS_ERR;
    }
    SetSessionKeyByChanId(conn->channelId, conn->appInfo.sessionKey, sizeof(conn->appInfo.sessionKey));
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
        cJSON_free(bytes);
        return SOFTBUS_ERR;
    }
    cJSON_free(bytes);
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

static int32_t CreateSessionConnNode(int events, int fd, int32_t chanId, const char *ip)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc fail in create session conn node.");
        return SOFTBUS_MALLOC_ERR;
    }
    conn->appInfo.myData.apiVersion = API_V2;
    conn->appInfo.fd = fd;
    conn->serverSide = true;
    conn->channelId = chanId;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_CONNECTING;
    conn->timeout = 0;

    if (LnnGetLocalStrInfo(STRING_KEY_UUID, conn->appInfo.myData.deviceId,
        sizeof(conn->appInfo.myData.deviceId)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get local deviceId failed.");
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }

    if (GetUuidFromAuth(ip, conn->appInfo.peerData.deviceId, DEVICE_ID_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusFree(conn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get uuid from from auth failed.");
        return SOFTBUS_ERR;
    }

    if (strcpy_s(conn->appInfo.peerData.ip, sizeof(conn->appInfo.peerData.ip), ip) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "copy ip to app info failed.");
        SoftBusFree(conn);
        return SOFTBUS_MEM_ERR;
    }

    char *authState = "";
    if (strcpy_s(conn->appInfo.myData.authState, sizeof(conn->appInfo.myData.authState), authState) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "copy auth state to app info failed.");
        SoftBusFree(conn);
        return SOFTBUS_MEM_ERR;
    }

    if (TransTdcAddSessionConn(conn) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add session conn node failed.");
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }

    if (AddTrigger(DIRECT_CHANNEL_SERVER, fd, READ_TRIGGER) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add trigger failed, delete session conn.");
        TransDelSessionConnById(chanId);
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

    int32_t channelId = GenerateTdcChannelId();
    int32_t ret = TransSrvAddDataBufNode(channelId, cfd); // fd != channelId
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create srv data buf node failed.");
        return ret;
    }

    ret = CreateSessionConnNode(events, cfd, channelId, ip);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create session conn node fail, delete data buf node.");
        TransSrvDelDataBufNode(channelId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t OnDataEvent(int events, int fd)
{
    SessionConn *conn = SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnDataEvent malloc fail.");
        return SOFTBUS_ERR;
    }
    if (GetSessionConnByFd(fd, conn) == NULL || conn->appInfo.fd != fd) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fd[%d] is not exist tdc info.", fd);
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }
    int32_t ret = SOFTBUS_ERR;
    if (events == SOFTBUS_SOCKET_IN) {
        ret = TransTdcSrvRecvData(conn->channelId);
        if (ret != SOFTBUS_DATA_NOT_ENOUGH) {
            DelTrigger(DIRECT_CHANNEL_SERVER, fd, READ_TRIGGER);
            CloseTcpFd(fd);
            if (ret != SOFTBUS_OK) {
                NotifyChannelOpenFailed(conn->channelId);
            }
            TransDelSessionConnById(conn->channelId);
            TransSrvDelDataBufNode(conn->channelId);
        }
    } else if (events == SOFTBUS_SOCKET_OUT) {
        if (conn->serverSide == true) {
            SoftBusFree(conn);
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
            TransDelSessionConnById(conn->channelId);
            TransSrvDelDataBufNode(conn->channelId);
        }
    } else if (events == SOFTBUS_SOCKET_EXCEPTION) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "exception occurred.");
        DelTrigger(DIRECT_CHANNEL_SERVER, fd, EXCEPT_TRIGGER);
        CloseTcpFd(fd);
        TransDelSessionConnById(conn->channelId);
        TransSrvDelDataBufNode(conn->channelId);
    }
    SoftBusFree(conn);
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
    DestroyBaseListener(DIRECT_CHANNEL_SERVER);
    return ret;
}

SoftbusBaseListener *TransTdcGetSessionListener(void)
{
    return g_sessionListener;
}

