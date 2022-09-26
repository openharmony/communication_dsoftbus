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
#include "p2plink_interface.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_message_open_channel.h"
#include "softbus_tcp_socket.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_sessionconn.h"

static SoftbusBaseListener g_sessionListener;

uint32_t SwitchAuthLinkTypeToFlagType(AuthLinkType type)
{
    switch (type) {
        case AUTH_LINK_TYPE_BR:
            return FLAG_BR;
        case AUTH_LINK_TYPE_BLE:
            return FLAG_BLE;
        case AUTH_LINK_TYPE_P2P:
            return FLAG_P2P;
        default:
            return FLAG_WIFI;
    }
}

uint32_t GetCipherFlagByAuthId(int64_t authId)
{
    AuthConnInfo info = {0};
    uint32_t flag = FLAG_WIFI;

    if (authId == AUTH_INVALID_ID) {
        return flag;
    }
    if (AuthGetConnInfo(authId, &info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "get authinfo fail %lld", authId);
        return flag;
    }
    flag = SwitchAuthLinkTypeToFlagType(info.type);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "get auth link type %d flag 0x%x", info.type, flag);
    return flag;
}

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
    uint32_t cipherFlag = GetCipherFlagByAuthId(conn->authId);
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = seq,
        .flags = (FLAG_REQUEST | cipherFlag),
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

static int32_t CreateSessionConnNode(ListenerModule module, int events, int fd, int32_t chanId, const char *ip)
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
    conn->listenMod = module;
    conn->authId = AUTH_INVALID_ID;

    if (LnnGetLocalStrInfo(STRING_KEY_UUID, conn->appInfo.myData.deviceId,
        sizeof(conn->appInfo.myData.deviceId)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get local deviceId failed.");
        SoftBusFree(conn);
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

    if (AddTrigger(conn->listenMod, fd, READ_TRIGGER) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add trigger failed, delete session conn.");
        TransDelSessionConnById(chanId);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t OnConnectEvent(ListenerModule module, int events, int cfd, const char *ip)
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
        TcpShutDown(cfd);
        return ret;
    }

    ret = CreateSessionConnNode(module, events, cfd, channelId, ip);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create session conn node fail, delete data buf node.");
        TransSrvDelDataBufNode(channelId);
        TcpShutDown(cfd);
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "tdc conn event fd:%d, cId:%d, module:%d.", cfd, channelId, module);
    return SOFTBUS_OK;
}

static void CloseTcpDirectFd(int fd)
{
#ifndef __LITEOS_M__
    CloseTcpFd(fd);
#else
    (void)fd;
#endif
}

static void TransProcDataRes(ListenerModule module, int32_t ret, int32_t channelId, int32_t fd)
{
    if (ret != SOFTBUS_OK) {
        DelTrigger(module, fd, READ_TRIGGER);
        TcpShutDown(fd);
        NotifyChannelOpenFailed(channelId);
    } else {
        CloseTcpDirectFd(fd);
    }
    TransDelSessionConnById(channelId);
    TransSrvDelDataBufNode(channelId);
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
        DelTrigger(conn->listenMod, fd, READ_TRIGGER);
        DelTrigger(conn->listenMod, fd, WRITE_TRIGGER);
        DelTrigger(conn->listenMod, fd, EXCEPT_TRIGGER);
        SoftBusFree(conn);
        TcpShutDown(fd);
        return SOFTBUS_ERR;
    }
    int32_t ret = SOFTBUS_ERR;
    if (events == SOFTBUS_SOCKET_IN) {
        ret = TransTdcSrvRecvData(conn->listenMod, conn->channelId);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "Trans Srv Recv Data ret %d. ", ret);
        if (ret == SOFTBUS_DATA_NOT_ENOUGH) {
            SoftBusFree(conn);
            return SOFTBUS_OK;
        }
        TransProcDataRes(conn->listenMod, ret, conn->channelId, fd);
    } else if (events == SOFTBUS_SOCKET_OUT) {
        if (conn->serverSide == true) {
            SoftBusFree(conn);
            return ret;
        }
        DelTrigger(conn->listenMod, fd, WRITE_TRIGGER);
        AddTrigger(conn->listenMod, fd, READ_TRIGGER);
        ret = StartVerifySession(conn);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "start verify session fail.");
            DelTrigger(conn->listenMod, fd, READ_TRIGGER);
            TcpShutDown(fd);
            NotifyChannelOpenFailed(conn->channelId);
            TransDelSessionConnById(conn->channelId);
            TransSrvDelDataBufNode(conn->channelId);
        }
    } else if (events == SOFTBUS_SOCKET_EXCEPTION) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "exception occurred.");
        DelTrigger(conn->listenMod, fd, EXCEPT_TRIGGER);
        TcpShutDown(fd);
        TransDelSessionConnById(conn->channelId);
        TransSrvDelDataBufNode(conn->channelId);
    }
    SoftBusFree(conn);
    return ret;
}

static int32_t OnConnectEventWifi(int32_t events, int32_t cfd, const char *ip)
{
    return OnConnectEvent(DIRECT_CHANNEL_SERVER_WIFI, events, cfd, ip);
}

static int32_t OnDataEventWifi(int32_t events, int32_t fd)
{
    return OnDataEvent(events, fd);
}

static int32_t OnConnectEventP2P(int32_t events, int32_t cfd, const char *ip)
{
    return OnConnectEvent(DIRECT_CHANNEL_SERVER_P2P, events, cfd, ip);
}

static int32_t OnDataEventP2P(int32_t events, int32_t fd)
{
    return OnDataEvent(events, fd);
}

int32_t TransTdcStartSessionListener(const char *ip, const int port)
{
    if (ip == NULL || port < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid para.");
        return SOFTBUS_INVALID_PARAM;
    }

    g_sessionListener.onConnectEvent = OnConnectEventWifi;
    g_sessionListener.onDataEvent = OnDataEventWifi;

    int32_t ret = SetSoftbusBaseListener(DIRECT_CHANNEL_SERVER_WIFI, &g_sessionListener);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Set BaseListener Failed.");
        return ret;
    }
    int serverPort = StartBaseListener(DIRECT_CHANNEL_SERVER_WIFI, ip, port, SERVER_MODE);
    return serverPort;
}

int32_t TransTdcStopSessionListener(void)
{
    TransTdcStopSessionProc();
    int32_t ret = StopBaseListener(DIRECT_CHANNEL_SERVER_WIFI);
    DestroyBaseListener(DIRECT_CHANNEL_SERVER_WIFI);
    return ret;
}

int32_t GetTdcBaseListener(SoftbusBaseListener *listener)
{
    if (listener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    listener->onConnectEvent = OnConnectEventP2P;
    listener->onDataEvent = OnDataEventP2P;
    return SOFTBUS_OK;
}
