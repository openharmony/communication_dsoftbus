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
#include "softbus_socket.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_sessionconn.h"

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

int32_t GetCipherFlagByAuthId(int64_t authId, uint32_t *flag, bool *isAuthServer)
{
    AuthConnInfo info;
    if (AuthGetServerSide(authId, isAuthServer) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get auth server side fail %" PRId64, authId);
        return SOFTBUS_ERR;
    }
    if (AuthGetConnInfo(authId, &info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get authinfo fail %" PRId64, authId);
        return SOFTBUS_ERR;
    }
    *flag = SwitchAuthLinkTypeToFlagType(info.type);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "get auth link type %d flag 0x%x", info.type, *flag);
    return SOFTBUS_OK;
}

static int32_t StartVerifySession(SessionConn *conn)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "StartVerifySession");
    if (SoftBusGenerateSessionKey(conn->appInfo.sessionKey, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Generate SessionKey failed");
        return SOFTBUS_ERR;
    }
    SetSessionKeyByChanId(conn->channelId, conn->appInfo.sessionKey, sizeof(conn->appInfo.sessionKey));

    bool isAuthServer = false;
    uint32_t cipherFlag = FLAG_WIFI;
    if (GetCipherFlagByAuthId(conn->authId, &cipherFlag, &isAuthServer)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get cipher flag failed");
        return SOFTBUS_ERR;
    }
    uint64_t seq = TransTdcGetNewSeqId();
    if (isAuthServer) {
        seq |= AUTH_CONN_SERVER_SIDE;
    }

    char *bytes = PackRequest(&conn->appInfo);
    if (bytes == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Pack Request failed");
        return SOFTBUS_ERR;
    }
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = seq,
        .flags = (FLAG_REQUEST | cipherFlag),
        .dataLen = strlen(bytes), /* reset after encrypt */
    };
    if (conn->isMeta) {
        packetHead.flags |= FLAG_AUTH_META;
    }
    if (TransTdcPostBytes(conn->channelId, &packetHead, bytes) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransTdc post bytes failed");
        cJSON_free(bytes);
        return SOFTBUS_ERR;
    }
    cJSON_free(bytes);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "StartVerifySession ok");

    return SOFTBUS_OK;
}

static int32_t CreateSessionConnNode(
    ListenerModule module, int events, int fd, int32_t chanId, const ConnectOption *clientAddr)
{
    (void)events;
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

    if (LnnGetLocalStrInfo(STRING_KEY_UUID, conn->appInfo.myData.deviceId, sizeof(conn->appInfo.myData.deviceId)) !=
        0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get local deviceId failed.");
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }

    if (strcpy_s(conn->appInfo.peerData.addr, sizeof(conn->appInfo.peerData.addr), clientAddr->socketOption.addr) !=
        EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "copy ip to app info failed.");
        SoftBusFree(conn);
        return SOFTBUS_MEM_ERR;
    }
    conn->appInfo.protocol = clientAddr->socketOption.protocol;

    const char *authState = "";
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

static int32_t TdcOnConnectEvent(ListenerModule module, int events, int cfd, const ConnectOption *clientAddr)
{
    if (events == SOFTBUS_SOCKET_EXCEPTION) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Exception occurred");
        return SOFTBUS_ERR;
    }
    if (cfd < 0 || clientAddr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param, cfd = %d", cfd);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = GenerateTdcChannelId();
    int32_t ret = TransSrvAddDataBufNode(channelId, cfd); // fd != channelId
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create srv data buf node failed.");
        ConnShutdownSocket(cfd);
        return ret;
    }

    ret = CreateSessionConnNode(module, events, cfd, channelId, clientAddr);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create session conn node fail, delete data buf node.");
        TransSrvDelDataBufNode(channelId);
        ConnShutdownSocket(cfd);
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "tdc conn event fd:%d, cId:%d, module:%d.", cfd, channelId, module);
    return SOFTBUS_OK;
}

static void CloseTcpDirectFd(int fd)
{
#ifndef __LITEOS_M__
    ConnCloseSocket(fd);
#else
    (void)fd;
#endif
}

static void TransProcDataRes(ListenerModule module, int32_t ret, int32_t channelId, int32_t fd)
{
    if (ret != SOFTBUS_OK) {
        DelTrigger(module, fd, READ_TRIGGER);
        ConnShutdownSocket(fd);
        NotifyChannelOpenFailed(channelId, ret);
    } else {
        CloseTcpDirectFd(fd);
    }
    TransDelSessionConnById(channelId);
    TransSrvDelDataBufNode(channelId);
}

static int32_t TdcOnDataEvent(ListenerModule module, int events, int fd)
{
    (void)module;
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnDataEvent malloc fail.");
        return SOFTBUS_ERR;
    }
    if (GetSessionConnByFd(fd, conn) == NULL || conn->appInfo.fd != fd) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fd[%d] is not exist tdc info. appfd=%d", conn->appInfo.fd, fd);
        DelTrigger(conn->listenMod, fd, READ_TRIGGER);
        DelTrigger(conn->listenMod, fd, WRITE_TRIGGER);
        DelTrigger(conn->listenMod, fd, EXCEPT_TRIGGER);
        SoftBusFree(conn);
        ConnShutdownSocket(fd);
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
            ConnShutdownSocket(fd);
            NotifyChannelOpenFailed(conn->channelId, ret);
            TransDelSessionConnById(conn->channelId);
            TransSrvDelDataBufNode(conn->channelId);
        }
    } else if (events == SOFTBUS_SOCKET_EXCEPTION) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "exception occurred.");
        DelTrigger(conn->listenMod, fd, EXCEPT_TRIGGER);
        ConnShutdownSocket(fd);
        TransDelSessionConnById(conn->channelId);
        TransSrvDelDataBufNode(conn->channelId);
    }
    SoftBusFree(conn);
    return ret;
}

int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info)
{
    if (info == NULL || (info->type != CONNECT_TCP && info->type != CONNECT_P2P) || info->socketOption.port < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s:Invalid para.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }

    static SoftbusBaseListener sessionListener = {
        .onConnectEvent = TdcOnConnectEvent,
        .onDataEvent = TdcOnDataEvent
    };

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "%s:set listener for module %d.", __func__, module);
    int32_t ret = SetSoftbusBaseListener(module, &sessionListener);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s:Set BaseListener Failed.", __func__);
        return ret;
    }
    int serverPort = StartBaseListener(info);
    return serverPort;
}

int32_t TransTdcStopSessionListener(ListenerModule module)
{
    TransTdcStopSessionProc(module);
    return StopBaseListener(module);
}
