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

#include <securec.h>

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_message_open_channel.h"
#include "softbus_socket.h"
#include "trans_channel_manager.h"
#include "trans_event.h"
#include "trans_log.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_sessionconn.h"

#define ID_OFFSET (1)

uint32_t SwitchAuthLinkTypeToFlagType(AuthLinkType type)
{
    switch (type) {
        case AUTH_LINK_TYPE_BR:
            return FLAG_BR;
        case AUTH_LINK_TYPE_BLE:
            return FLAG_BLE;
        case AUTH_LINK_TYPE_P2P:
            return FLAG_P2P;
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            return FLAG_ENHANCE_P2P;
        default:
            return FLAG_WIFI;
    }
}

int32_t GetCipherFlagByAuthId(int64_t authId, uint32_t *flag, bool *isAuthServer)
{
    if (flag == NULL || isAuthServer == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthConnInfo info;
    if (AuthGetServerSide(authId, isAuthServer) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get auth server side fail authId=%{public}" PRId64, authId);
        return SOFTBUS_ERR;
    }
    if (AuthGetConnInfo(authId, &info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get authinfo fail authId=%{public}" PRId64, authId);
        return SOFTBUS_ERR;
    }
    *flag = SwitchAuthLinkTypeToFlagType(info.type);
    TRANS_LOGI(TRANS_CTRL, "get auth link type=%{public}d, flag=0x%{public}x", info.type, *flag);
    return SOFTBUS_OK;
}

static int32_t StartVerifySession(SessionConn *conn)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    if (SoftBusGenerateSessionKey(conn->appInfo.sessionKey, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Generate SessionKey failed");
        return SOFTBUS_TRANS_TCP_GENERATE_SESSIONKEY_FAILED;
    }
    SetSessionKeyByChanId(conn->channelId, conn->appInfo.sessionKey, sizeof(conn->appInfo.sessionKey));
    bool isAuthServer = false;
    uint32_t cipherFlag = FLAG_WIFI;
    if (GetCipherFlagByAuthId(conn->authId, &cipherFlag, &isAuthServer)) {
        TRANS_LOGE(TRANS_CTRL, "get cipher flag failed");
        return SOFTBUS_TRANS_GET_CIPHER_FAILED;
    }
    uint64_t seq = TransTdcGetNewSeqId();
    if (isAuthServer) {
        seq |= AUTH_CONN_SERVER_SIDE;
    }
    char *bytes = PackRequest(&conn->appInfo);
    if (bytes == NULL) {
        TRANS_LOGE(TRANS_CTRL, "Pack Request failed");
        return SOFTBUS_TRANS_PACK_REQUEST_FAILED;
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
    int32_t ret = TransTdcPostBytes(conn->channelId, &packetHead, bytes);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "TransTdc post bytes failed");
        cJSON_free(bytes);
        return ret;
    }
    cJSON_free(bytes);
    TRANS_LOGI(TRANS_CTRL, "ok");

    return SOFTBUS_OK;
}

static int32_t CreateSessionConnNode(ListenerModule module, int fd, int32_t chanId, const ConnectOption *clientAddr)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc fail in create session conn node.");
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
    conn->appInfo.routeType = ((module == DIRECT_CHANNEL_SERVER_P2P) || (module >= DIRECT_CHANNEL_SERVER_HML_START &&
        module <= DIRECT_CHANNEL_SERVER_HML_END)) ? WIFI_P2P : WIFI_STA;
    conn->appInfo.routeType = (module == DIRECT_CHANNEL_SERVER_P2P) ? WIFI_P2P : WIFI_STA;
    conn->appInfo.peerData.port = clientAddr->socketOption.port;
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, conn->appInfo.myData.deviceId, sizeof(conn->appInfo.myData.deviceId)) !=
        0) {
        TRANS_LOGE(TRANS_CTRL, "get local deviceId failed.");
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }
    if (strcpy_s(conn->appInfo.peerData.addr, sizeof(conn->appInfo.peerData.addr), clientAddr->socketOption.addr) !=
        EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy ip to app info failed.");
        SoftBusFree(conn);
        return SOFTBUS_MEM_ERR;
    }
    conn->appInfo.protocol = clientAddr->socketOption.protocol;

    const char *authState = "";
    if (strcpy_s(conn->appInfo.myData.authState, sizeof(conn->appInfo.myData.authState), authState) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy auth state to app info failed.");
        SoftBusFree(conn);
        return SOFTBUS_MEM_ERR;
    }
    if (TransTdcAddSessionConn(conn) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "add session conn node failed.");
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }
    if (AddTrigger(conn->listenMod, fd, READ_TRIGGER) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "add trigger failed, delete session conn.");
        TransDelSessionConnById(chanId);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t TdcOnConnectEvent(ListenerModule module, int cfd, const ConnectOption *clientAddr)
{
    if (cfd < 0 || clientAddr == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param, cfd=%{public}d", cfd);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t channelId = GenerateChannelId(true);
    int32_t ret = TransSrvAddDataBufNode(channelId, cfd); // fd != channelId
    TransEventExtra extra = {
        .socketName = NULL,
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .socketFd = cfd,
        .channelId = channelId
    };
    if (ret != SOFTBUS_OK) {
        extra.result = EVENT_STAGE_RESULT_FAILED;
        extra.errcode = ret;
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_START_CONNECT, extra);
        TRANS_LOGE(TRANS_CTRL, "create srv data buf node failed.");
        ConnShutdownSocket(cfd);
        return ret;
    }
    ret = CreateSessionConnNode(module, cfd, channelId, clientAddr);
    if (ret != SOFTBUS_OK) {
        extra.result = EVENT_STAGE_RESULT_FAILED;
        extra.errcode = ret;
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_START_CONNECT, extra);
        TRANS_LOGE(TRANS_CTRL, "create session conn node fail, delete data buf node.");
        TransSrvDelDataBufNode(channelId);
        ConnShutdownSocket(cfd);
        return ret;
    }
    extra.result = EVENT_STAGE_RESULT_OK;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_START_CONNECT, extra);
    TRANS_LOGI(TRANS_CTRL,
        "tdc conn event cfd=%{public}d, channelId=%{public}d, module=%{public}d", cfd, channelId, module);
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
        TRANS_LOGI(TRANS_CTRL, "unequal SOFTBUS_OK");
        TransEventExtra extra = {
            .socketName = NULL,
            .peerNetworkId = NULL,
            .calleePkg = NULL,
            .callerPkg = NULL,
            .channelId = channelId,
            .socketFd = fd,
            .errcode = ret,
            .result = EVENT_STAGE_RESULT_FAILED
        };
        SessionConn conn;
        if (GetSessionConnById(channelId, &conn) == NULL || !conn.serverSide) {
            TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_REPLY, extra);
        } else {
            TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_REPLY, extra);
        }
        DelTrigger(module, fd, READ_TRIGGER);
        ConnShutdownSocket(fd);
        NotifyChannelOpenFailed(channelId, ret);
    } else {
        CloseTcpDirectFd(fd);
    }
    TransDelSessionConnById(channelId);
    TransSrvDelDataBufNode(channelId);
}

static int32_t ProcessSocketInEvent(SessionConn *conn, int fd)
{
    int32_t ret = TransTdcSrvRecvData(conn->listenMod, conn->channelId);
    TRANS_LOGE(TRANS_CTRL, "Trans Srv Recv Data ret=%{public}d. ", ret);
    if (ret == SOFTBUS_DATA_NOT_ENOUGH) {
        return SOFTBUS_OK;
    }
    TransProcDataRes(conn->listenMod, ret, conn->channelId, fd);
    return ret;
}

static int32_t ProcessSocketOutEvent(SessionConn *conn, int fd)
{
    int32_t ret = SOFTBUS_ERR;
    if (conn->serverSide) {
        return ret;
    }
    DelTrigger(conn->listenMod, fd, WRITE_TRIGGER);
    AddTrigger(conn->listenMod, fd, READ_TRIGGER);
    ret = StartVerifySession(conn);
    TransEventExtra extra = { .socketName = NULL,
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .socketFd = fd,
        .channelId = conn->channelId,
        .authId = conn->authId,
        .errcode = ret,
        .result = (ret == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_START, extra);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "start verify session fail.");
        DelTrigger(conn->listenMod, fd, READ_TRIGGER);
        ConnShutdownSocket(fd);
        NotifyChannelOpenFailed(conn->channelId, ret);
        TransDelSessionConnById(conn->channelId);
        TransSrvDelDataBufNode(conn->channelId);
    }
    return ret;
}

static void ProcessSocketSocketExceptionEvent(SessionConn *conn, int fd)
{
    TRANS_LOGE(TRANS_CTRL, "exception occurred.");
    DelTrigger(conn->listenMod, fd, EXCEPT_TRIGGER);
    ConnShutdownSocket(fd);
    TransDelSessionConnById(conn->channelId);
    TransSrvDelDataBufNode(conn->channelId);
}

static int32_t TdcOnDataEvent(ListenerModule module, int events, int fd)
{
    (void)module;
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        TRANS_LOGE(TRANS_CTRL, "OnDataEvent malloc fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (GetSessionConnByFd(fd, conn) == NULL || conn->appInfo.fd != fd) {
        TRANS_LOGE(TRANS_CTRL, "fd=%{public}d is not exist tdc info. appfd=%{public}d", fd, conn->appInfo.fd);
        for (uint32_t i = DIRECT_CHANNEL_SERVER_P2P; i <= DIRECT_CHANNEL_SERVER_HML_END; i++) {
            DelTrigger(i, fd, READ_TRIGGER);
            DelTrigger(i, fd, WRITE_TRIGGER);
            DelTrigger(i, fd, EXCEPT_TRIGGER);
        }
        SoftBusFree(conn);
        ConnShutdownSocket(fd);
        return SOFTBUS_INVALID_FD;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)(conn->channelId + ID_OFFSET));
    int32_t ret = SOFTBUS_ERR;
    if (events == SOFTBUS_SOCKET_IN) {
        ret = ProcessSocketInEvent(conn, fd);
    } else if (events == SOFTBUS_SOCKET_OUT) {
        ret = ProcessSocketOutEvent(conn, fd);
    } else if (events == SOFTBUS_SOCKET_EXCEPTION) {
        ProcessSocketSocketExceptionEvent(conn, fd);
    }
    SoftBusFree(conn);
    return ret;
}

int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info)
{
    if (info == NULL || (info->type != CONNECT_TCP && info->type != CONNECT_P2P) || info->socketOption.port < 0) {
        TRANS_LOGE(TRANS_CTRL, "Invalid para.");
        return SOFTBUS_INVALID_PARAM;
    }

    static SoftbusBaseListener sessionListener = {
        .onConnectEvent = TdcOnConnectEvent,
        .onDataEvent = TdcOnDataEvent
    };

    TRANS_LOGI(TRANS_CTRL, "set listener for module=%{public}d.", module);
    int serverPort = StartBaseListener(info, &sessionListener);
    return serverPort;
}

int32_t TransTdcStopSessionListener(ListenerModule module)
{
    TransTdcStopSessionProc(module);
    return StopBaseListener(module);
}