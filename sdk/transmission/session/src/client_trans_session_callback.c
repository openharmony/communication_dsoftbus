/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "client_trans_session_callback.h"

#include <securec.h>
#include <unistd.h>

#include "anonymizer.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_udp_manager.h"
#include "g_enhance_sdk_func.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_log.h"
#include "trans_split_serviceid.h"

#define RETRY_GET_INFO_TIMES_MS 300

static IClientSessionCallBack g_sessionCb;

static int32_t FillSessionInfoEx(SessionInfo *session, const ChannelInfo *channel)
{
    if (strcpy_s(session->info.peerSessionName, SESSION_NAME_SIZE_MAX, channel->peerSessionName) != EOK ||
        strcpy_s(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX, channel->peerDeviceId) != EOK ||
        strcpy_s(session->info.groupId, GROUP_ID_SIZE_MAX, channel->groupId) != EOK) {
        TRANS_LOGE(TRANS_SDK, "client or peer session name, device id, group id failed");
        return SOFTBUS_STRCPY_ERR;
    }
    if (channel->tokenType > ACCESS_TOKEN_TYPE_HAP && channel->peerBusinessAccountId != NULL) {
        session->peerUserId = channel->peerUserId;
        session->peerTokenId = channel->peerTokenId;
        if (channel->peerBusinessAccountId != NULL &&
            strcpy_s(session->peerBusinessAccountId, ACCOUNT_UID_LEN_MAX, channel->peerBusinessAccountId) != EOK) {
            TRANS_LOGE(TRANS_SDK, "copy accountId failed");
            return SOFTBUS_STRCPY_ERR;
        }
        if (channel->peerExtraAccessInfo != NULL &&
            strcpy_s(session->peerExtraAccessInfo, EXTRA_ACCESS_INFO_LEN_MAX, channel->peerExtraAccessInfo) != EOK) {
            TRANS_LOGE(TRANS_SDK, "copy extraAccessInfo failed");
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t FillSessionInfo(SessionInfo *session, const ChannelInfo *channel, uint32_t flag)
{
    session->channelId = channel->channelId;
    session->channelType = (ChannelType)channel->channelType;
    session->routeType = channel->routeType;
    session->enableMultipath = channel->enableMultipath;
    session->peerPid = channel->peerPid;
    session->peerUid = channel->peerUid;
    session->isServer = channel->isServer;
    session->enableStatus = ENABLE_STATUS_SUCCESS;
    session->info.flag = (int32_t)flag;
    session->isEncrypt = channel->isEncrypt;
    session->businessType = channel->businessType;
    session->routeType = channel->routeType;
    session->fileEncrypt = channel->fileEncrypt;
    session->algorithm = channel->algorithm;
    session->crc = channel->crc;
    session->dataConfig = channel->dataConfig;
    session->isAsync = false;
    session->osType = channel->osType;
    session->lifecycle.sessionState = SESSION_STATE_CALLBACK_FINISHED;
    session->isSupportTlv = channel->isSupportTlv;
    session->tokenType = channel->tokenType;
    if (channel->isD2D) {
        session->isD2D = channel->isD2D;
        session->dataLen = channel->dataLen;
        if (channel->dataLen > 0 && channel->dataLen <= EXTRA_DATA_MAX_LEN &&
            memcpy_s(session->extraData, EXTRA_DATA_MAX_LEN, channel->extraData, channel->dataLen) != EOK) {
            TRANS_LOGE(TRANS_SDK, "copy extraData failed");
            return SOFTBUS_MEM_ERR;
        }
        if (channel->isServer &&
            strcpy_s(session->peerPagingAccountId, ACCOUNT_UID_LEN_MAX, channel->pagingAccountId) != EOK) {
            TRANS_LOGE(TRANS_SDK, "copy peerPagingAccountId failed");
            return SOFTBUS_STRCPY_ERR;
        }
        if (strcpy_s(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX, channel->peerDeviceId) != EOK) {
            TRANS_LOGE(TRANS_SDK, "copy peerDeviceId failed");
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    }
    return FillSessionInfoEx(session, channel);
}

static int32_t AcceptSessionAsServer(
    const char *sessionName, const ChannelInfo *channel, uint32_t flag, int32_t *sessionId)
{
    TRANS_LOGD(TRANS_SDK, "enter.");
    SessionInfo *session = (SessionInfo *)SoftBusCalloc(sizeof(SessionInfo));
    if (session == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = FillSessionInfo(session, channel, flag);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "fill session info failed, ret=%{public}d", ret);
        SoftBusFree(session);
        return ret;
    }
    ret = ClientAddNewSession(sessionName, session);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "client add session failed, ret=%{public}d", ret);
        SoftBusFree(session);
        return ret;
    }
    *sessionId = session->sessionId;
    TRANS_LOGD(TRANS_SDK, "ok");
    return SOFTBUS_OK;
}

static int32_t GetSessionCallbackByChannelId(
    int32_t channelId, int32_t channelType, int32_t *sessionId, ISessionListener *listener)
{
    if ((channelId < 0) || (sessionId == NULL) || (listener == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ClientGetSessionIdByChannelId(channelId, channelType, sessionId, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get sessionId failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    ret = ClientGetSessionCallbackById(*sessionId, listener);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get session listener failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t GetSocketCallbackAdapterByChannelId(
    int32_t channelId, int32_t channelType, int32_t *sessionId, SessionListenerAdapter *sessionCallback, bool *isServer)
{
    if ((channelId < 0) || (sessionId == NULL) || (sessionCallback == NULL) || (isServer == NULL)) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = ClientGetSessionIdByChannelId(channelId, channelType, sessionId, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get sessionId failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    ret = ClientGetSessionCallbackAdapterById(*sessionId, sessionCallback, isServer);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK,
            "get socket callback failed, channelId=%{public}d,"
            "ret=%{public}d",
            channelId, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t GetSocketCallbackAdapterByUdpChannelId(
    int32_t channelId, int32_t channelType, int32_t *sessionId, SessionListenerAdapter *sessionCallback, bool *isServer)
{
    if ((channelId < 0) || (sessionId == NULL) || (sessionCallback == NULL) || (isServer == NULL)) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = ClientGetSessionIdByChannelId(channelId, channelType, sessionId, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get sessionId failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    ret = ClientGetSessionCallbackAdapterById(*sessionId, sessionCallback, isServer);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get socket callback failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t TransOnBindSuccess(int32_t sessionId, const ISocketListener *socketCallback)
{
    if (socketCallback == NULL || socketCallback->OnBind == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid OnBind callback function");
        return SOFTBUS_INVALID_PARAM;
    }

    PeerSocketInfo info;
    int32_t ret = ClientGetPeerSocketInfoById(sessionId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Get peer socket info failed, ret=%{public}d", ret);
        return ret;
    }

    (void)socketCallback->OnBind(sessionId, info);
    return SOFTBUS_OK;
}

static int32_t TransOnServiceBindSuccess(int32_t sessionId, const ISocketListener *socketCallback)
{
    if (socketCallback == NULL || socketCallback->OnServiceBind == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid OnServiceBind callback function");
        return SOFTBUS_INVALID_PARAM;
    }

    ServiceSocketInfo info;
    int32_t ret = ClientGetServiceSocketInfoById(sessionId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Get service socket info failed, ret=%{public}d", ret);
        return ret;
    }

    socketCallback->OnServiceBind(sessionId, info);
    return SOFTBUS_OK;
}

static int32_t TransOnBindFailed(int32_t sessionId, const ISocketListener *socketCallback, int32_t errCode)
{
    (void)ClientHandleBindWaitTimer(sessionId, 0, TIMER_ACTION_STOP);
    bool isAsync = true;
    int32_t ret = ClientGetSessionIsAsyncBySessionId(sessionId, &isAsync);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get is async type failed, sessionId=%{public}d, ret=%{public}d", sessionId, ret);
        return ret;
    }
    if (!isAsync) {
        (void)ClientSignalSyncBind(sessionId, errCode);
        return SOFTBUS_OK;
    }
    if (socketCallback == NULL || socketCallback->OnError == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid OnBind callback function");
        return SOFTBUS_INVALID_PARAM;
    }

    SocketLifecycleData lifecycle;
    (void)memset_s(&lifecycle, sizeof(SocketLifecycleData), 0, sizeof(SocketLifecycleData));
    ret = GetSocketLifecycleAndSessionNameBySessionId(sessionId, NULL, &lifecycle);
    (void)SetSessionStateBySessionId(sessionId, SESSION_STATE_INIT, 0);
    if (ret == SOFTBUS_OK && lifecycle.sessionState == SESSION_STATE_CANCELLING) {
        TRANS_LOGW(TRANS_SDK, "socket is cancelling, no need call back, socket=%{public}d, bindErrCode=%{public}d",
            sessionId, lifecycle.bindErrCode);
        return lifecycle.bindErrCode;
    }

    (void)socketCallback->OnError(sessionId, errCode);
    TRANS_LOGI(TRANS_SDK, "OnError success, client socket=%{public}d", sessionId);
    return SOFTBUS_OK;
}

static int32_t HandleAsyncBindSuccess(
    int32_t sessionId, const ISocketListener *socketClient, const SocketLifecycleData *lifecycle)
{
    int32_t ret = ClientHandleBindWaitTimer(sessionId, 0, TIMER_ACTION_STOP);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "stop bind wait timer failed, ret=%{public}d", ret);
        return ret;
    }
    if (lifecycle->sessionState == SESSION_STATE_CANCELLING) {
        TRANS_LOGW(TRANS_SDK, "session is cancelling, no need call back");
        return SOFTBUS_OK;
    }
    ret = SetSessionStateBySessionId(sessionId, SESSION_STATE_CALLBACK_FINISHED, 0);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "set session state failed, ret=%{public}d", ret);
        return ret;
    }

    bool isContain = IsContainServiceBySocket(sessionId);
    if (!isContain) {
        return TransOnBindSuccess(sessionId, socketClient);
    }
    return TransOnServiceBindSuccess(sessionId, socketClient);
}

static int32_t TransOnNegotiate(int32_t socket, const ISocketListener *socketCallback)
{
    if (socketCallback == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid socketCallback socket=%{public}d", socket);
        return SOFTBUS_INVALID_PARAM;
    }

    if (socketCallback->OnNegotiate == NULL) {
        TRANS_LOGW(TRANS_SDK, "no OnNegotiate callback function socket=%{public}d", socket);
        return SOFTBUS_OK;
    }

    PeerSocketInfo info = { 0 };
    int32_t ret = ClientGetPeerSocketInfoById(socket, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Get peer socket info failed, ret=%{public}d, socket=%{public}d", ret, socket);
        return ret;
    }

    if (!socketCallback->OnNegotiate(socket, info)) {
        TRANS_LOGW(TRANS_SDK, "The negotiate rejected the socket=%{public}d", socket);
        return SOFTBUS_TRANS_NEGOTIATE_REJECTED;
    }

    return SOFTBUS_OK;
}

static int32_t TransOnNegotiate2(int32_t socket, const ISocketListener *socketCallback, const ChannelInfo *channel,
    SocketAccessInfo *localAccessInfo)
{
    if (socketCallback == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid socketCallback socket=%{public}d", socket);
        return SOFTBUS_INVALID_PARAM;
    }

    if (socketCallback->OnNegotiate2 == NULL) {
        TRANS_LOGW(TRANS_SDK, "no OnNegotiate2 callback function socket=%{public}d", socket);
        return SOFTBUS_OK;
    }

    if (channel->peerUserId == -1) {
        TRANS_LOGW(TRANS_SDK, "default access info, no need check acl, socket=%{public}d", socket);
        return SOFTBUS_OK;
    }
    PeerSocketInfo socketInfo = { 0 };
    int32_t ret = ClientGetPeerSocketInfoById(socket, &socketInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Get peer access info failed, ret=%{public}d, socket=%{public}d", ret, socket);
        return ret;
    }

    SocketAccessInfo peerAccessInfo = {
        .userId = channel->peerUserId,
        .localTokenId = channel->peerTokenId,
        .businessAccountId = channel->peerBusinessAccountId,
        .extraAccessInfo = channel->peerExtraAccessInfo,
    };

    if (!socketCallback->OnNegotiate2(socket, socketInfo, &peerAccessInfo, localAccessInfo)) {
        TRANS_LOGW(TRANS_SDK, "The OnNegotiate2 rejected the socket=%{public}d", socket);
        return SOFTBUS_TRANS_NEGOTIATE_REJECTED;
    }

    return SOFTBUS_OK;
}

static int32_t TransOnServiceNegotiate(int32_t socket, const ISocketListener *socketCallback)
{
    if (socketCallback == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid socketCallback socket=%{public}d", socket);
        return SOFTBUS_INVALID_PARAM;
    }

    if (socketCallback->OnServiceNegotiate == NULL) {
        TRANS_LOGW(TRANS_SDK, "no OnServiceNegotiate callback function socket=%{public}d", socket);
        return SOFTBUS_OK;
    }

    ServiceSocketInfo info = { 0 };
    int32_t ret = ClientGetServiceSocketInfoById(socket, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Get service socket info failed, ret=%{public}d, socket=%{public}d", ret, socket);
        return ret;
    }

    if (!socketCallback->OnServiceNegotiate(socket, info)) {
        TRANS_LOGW(TRANS_SDK, "The negotiate rejected the socket=%{public}d", socket);
        return SOFTBUS_TRANS_NEGOTIATE_REJECTED;
    }

    return SOFTBUS_OK;
}

static int32_t HandleServerOnNegotiate(int32_t socket, int32_t tokenType, const ISocketListener *socketCallback,
    const ChannelInfo *channel, SocketAccessInfo *localAccessInfo)
{
    if (socketCallback == NULL || socketCallback->OnBind == NULL || channel == NULL) {
        TRANS_LOGE(TRANS_SDK, "OnBind exception, terminating this call, socket=%{public}d", socket);
        (void)ClientDeleteSocketSession(socket);
        return SOFTBUS_TRANS_SERVER_NOT_LISTEN;
    }

    bool isContain = IsContainServiceBySocket(socket);
    int32_t ret =
        isContain ? TransOnServiceNegotiate(socket, socketCallback) : TransOnNegotiate(socket, socketCallback);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "TransOn%{public}sNegotiate failed, ret=%{public}d", isContain ? "Service" : "", ret);
        (void)ClientDeleteSocketSession(socket);
        return ret;
    }

    if (tokenType > ACCESS_TOKEN_TYPE_HAP && channel->channelType != CHANNEL_TYPE_AUTH) {
        ret = TransOnNegotiate2(socket, socketCallback, channel, localAccessInfo);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "TransOnNegotiate2 failed, ret=%{public}d", ret);
            (void)ClientDeleteSocketSession(socket);
            return ret;
        }
    }
    return SOFTBUS_OK;
}

static int32_t HandleCacheQosEvent(int32_t socket, SessionListenerAdapter sessionCallback, bool isServer)
{
    if (isServer) {
        TRANS_LOGD(TRANS_SDK, "server side no need to handle cache qos event");
        return SOFTBUS_OK;
    }
    if (sessionCallback.socketClient.OnQos == NULL) {
        TRANS_LOGD(TRANS_SDK, "no OnQos callback function socket=%{public}d", socket);
        return SOFTBUS_OK;
    }
    CachedQosEvent cachedQosEvent;
    (void)memset_s(&cachedQosEvent, sizeof(CachedQosEvent), 0, sizeof(CachedQosEvent));
    int32_t ret = ClientGetCachedQosEventBySocket(socket, &cachedQosEvent);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get cached qos event failed, ret=%{public}d", ret);
        return ret;
    }
    if (cachedQosEvent.count > 0) {
        TRANS_LOGI(TRANS_SDK, "trigger OnQos callback, socket=%{public}d", socket);
        sessionCallback.socketClient.OnQos(
            socket, cachedQosEvent.event, (const QosTV *)cachedQosEvent.qos, cachedQosEvent.count);
    }
    return SOFTBUS_OK;
}

static int32_t HandleSyncBindSuccess(int32_t sessionId, const SocketLifecycleData *lifecycle)
{
    if (lifecycle->sessionState == SESSION_STATE_CANCELLING) {
        TRANS_LOGW(
            TRANS_SDK, "socket=%{public}d is cancelling, bindErrCode=%{public}d", sessionId, lifecycle->bindErrCode);
        return SOFTBUS_OK;
    }

    int32_t ret = ClientSignalSyncBind(sessionId, 0);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "sync signal bind failed, ret=%{public}d, socket=%{public}d", ret, sessionId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t HandleOnBindSuccess(int32_t sessionId, SessionListenerAdapter sessionCallback,
    const ChannelInfo *channel, SocketAccessInfo *sinkAccessInfo)
{
    // async bind call back client and server， sync bind only call back server.
    bool isAsync = true;
    int32_t tokenType = -1;
    int32_t ret = GetIsAsyncAndTokenTypeBySessionId(sessionId, &isAsync, &tokenType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Get is async type failed");
        return ret;
    }

    SocketLifecycleData lifecycle;
    (void)memset_s(&lifecycle, sizeof(SocketLifecycleData), 0, sizeof(SocketLifecycleData));
    ret = GetSocketLifecycleAndSessionNameBySessionId(sessionId, NULL, &lifecycle);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Get session lifecycle failed, ret=%{public}d", ret);
        return ret;
    }
    if (!channel->isServer) {
        (void)SetStartTimestampBySessionId(sessionId);
    }

    if (channel->isServer) {
        return HandleServerOnNegotiate(sessionId, tokenType, &sessionCallback.socketServer, channel, sinkAccessInfo);
    } else if (isAsync) {
        ret = HandleAsyncBindSuccess(sessionId, &sessionCallback.socketClient, &lifecycle);
        (void)HandleCacheQosEvent(sessionId, sessionCallback, channel->isServer);
        return ret;
    } else { // sync bind
        ret = HandleSyncBindSuccess(sessionId, &lifecycle);
        (void)HandleCacheQosEvent(sessionId, sessionCallback, channel->isServer);
        return ret;
    }

    return SOFTBUS_OK;
}

static void AnonymizeLogTransOnSessionOpenedInfo(const char *sessionName, const ChannelInfo *channel, SessionType flag)
{
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_SDK,
        "TransOnSessionOpened: sessionName=%{public}s, channelId=%{public}d, channelType=%{public}d, flag=%{public}d,"
        "isServer=%{public}d, type=%{public}d, crc=%{public}d",
        AnonymizeWrapper(tmpName), channel->channelId, channel->channelType, flag, channel->isServer,
        channel->routeType, channel->crc);
    AnonymizeFree(tmpName);
}

static int32_t ClientCheckFuncPointer(void *func)
{
    if (func == NULL) {
        TRANS_LOGE(TRANS_SDK, "enhance func not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return SOFTBUS_OK;
}

static int32_t TransOnPagingConnectPacked(const int32_t socket, const ChannelInfo *channel)
{
    ClientEnhanceFuncList *pfnClientEnhanceFuncList = ClientEnhanceFuncListGet();
    if (ClientCheckFuncPointer((void *)pfnClientEnhanceFuncList->transOnPagingConnect) != SOFTBUS_OK) {
        return SOFTBUS_FUNC_NOT_SUPPORT;
    }
    return pfnClientEnhanceFuncList->transOnPagingConnect(socket, channel);
}

static int32_t TransOnPagingSessionOpened(const char *sessionName, const ChannelInfo *channel, SessionType flag)
{
    int32_t socket = INVALID_SESSION_ID;
    SessionListenerAdapter sessionCallback;
    bool isServer = false;
    (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
    int32_t ret = GetSocketCallbackAdapterByChannelId(
        channel->channelId, channel->channelType, &socket, &sessionCallback, &isServer);
    if (ret == SOFTBUS_OK) {
        ret = ClientEnableSessionByChannelId(channel, &socket);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "enable session failed, ret=%{public}d", ret);
            return ret;
        }
        ret = TransOnBindSuccess(socket, &sessionCallback.socketServer);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "fork paging on bind failed, channelId=%{public}d", channel->channelId);
            return ret;
        }
        TRANS_LOGI(TRANS_SDK, "fork ok, channelId=%{public}d", channel->channelId);
        return SOFTBUS_OK;
    }
    ret = AcceptSessionAsServer(sessionName, channel, flag, &socket);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "accept paging session failed, ret=%{public}d", ret);
        return ret;
    }
    return TransOnPagingConnectPacked(socket, channel);
}

int32_t TransOnSessionOpened(
    const char *sessionName, const ChannelInfo *channel, SessionType flag, SocketAccessInfo *accessInfo)
{
    if ((sessionName == NULL) || (channel == NULL) || (accessInfo == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AnonymizeLogTransOnSessionOpenedInfo(sessionName, channel, flag);
    SessionListenerAdapter sessionCallback;
    (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
    int32_t ret = ClientGetSessionCallbackAdapterByName(sessionName, &sessionCallback);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get session listener failed, ret=%{public}d", ret);
        return ret;
    }
    if (!channel->isServer && channel->isD2D) {
        return TransOnPagingSessionOpened(sessionName, channel, flag);
    }
    int32_t sessionId = INVALID_SESSION_ID;
    if (channel->isServer) {
        int32_t multiPathSessionId = INVALID_SESSION_ID;
        bool isMultiPathSession = IsMultiPathSession(sessionName, &multiPathSessionId);
        if (isMultiPathSession) {
            int32_t ret = UpdateMultiPathSessionInfo(multiPathSessionId, channel);
            if (ret != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_SDK, "fill mp session info failed, ret=%{public}d", ret);
                return ret;
            }
            if (channel->channelType == CHANNEL_TYPE_UDP) {
                TransSetUdpChannelSessionId(channel->channelId, multiPathSessionId);
            }
            TRANS_LOGI(TRANS_SDK, "ok");
            return SOFTBUS_OK;
        }
        ret = AcceptSessionAsServer(sessionName, channel, flag, &sessionId);
    } else {
        ret = ClientEnableSessionByChannelId(channel, &sessionId);
        if (ret == SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND) {
            SoftBusSleepMs(RETRY_GET_INFO_TIMES_MS); // avoid set channel info later than sesssion opened callback
            ret = ClientEnableSessionByChannelId(channel, &sessionId);
        }
    }

    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "accept session failed, ret=%{public}d", ret);
        return ret;
    }
    if (channel->channelType == CHANNEL_TYPE_UDP) {
        TransSetUdpChannelSessionId(channel->channelId, sessionId);
    }
    if (sessionCallback.isSocketListener) {
        ret = HandleOnBindSuccess(sessionId, sessionCallback, channel, accessInfo);
        return ret;
    }
    TRANS_LOGD(TRANS_SDK, "trigger session open callback");
    if ((sessionCallback.session.OnSessionOpened == NULL) ||
        (sessionCallback.session.OnSessionOpened(sessionId, SOFTBUS_OK) != SOFTBUS_OK)) {
        TRANS_LOGE(TRANS_SDK, "OnSessionOpened failed");
        (void)ClientDeleteSession(sessionId);
        return SOFTBUS_TRANS_ON_SESSION_OPENED_FAILED;
    }
    TRANS_LOGI(TRANS_SDK, "ok, sessionId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

int32_t TransOnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    int32_t sessionId = INVALID_SESSION_ID;
    SessionListenerAdapter sessionCallback;
    (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
    if (channelType == CHANNEL_TYPE_UNDEFINED) {
        sessionId = channelId;
        (void)ClientSetEnableStatusBySocket(sessionId, ENABLE_STATUS_FAILED);
        // only client async bind failed call
        bool tmpIsServer = false;
        ClientGetSessionCallbackAdapterById(sessionId, &sessionCallback, &tmpIsServer);
        (void)TransOnBindFailed(sessionId, &sessionCallback.socketClient, errCode);
        return SOFTBUS_OK;
    }
    TRANS_LOGI(TRANS_SDK, "trigger session open failed callback, channelId=%{public}d, channelType=%{public}d",
        channelId, channelType);
    bool isServer = false;
    int32_t ret = GetSocketCallbackAdapterByChannelId(channelId, channelType, &sessionId, &sessionCallback, &isServer);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Get Socket Callback Adapter failed, ret=%{public}d", ret);
        return ret;
    }
    if (sessionCallback.isSocketListener) {
        int32_t useType = 3;
        (void)CheckChannelIsReserveByChannelId(sessionId, channelId, &useType);
        if (useType == 2) {
            TRANS_LOGI(TRANS_SDK, "sessionId=%{public}d, sessionId=%{public}d, useType=%{public}d, set fail", sessionId,
                channelId, useType);
            return SOFTBUS_OK;
        }
        (void)ClientSetEnableStatusBySocket(sessionId, ENABLE_STATUS_FAILED);
        bool isAsync = true;
        int ret = ClientGetSessionIsAsyncBySessionId(sessionId, &isAsync);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "get is async type failed, ret=%{public}d", ret);
            return ret;
        }

        if (isServer) {
            (void)ClientDeleteSocketSession(sessionId);
        } else if (isAsync) {
            (void)TransOnBindFailed(sessionId, &sessionCallback.socketClient, errCode);
        } else { // sync bind
            (void)ClientSignalSyncBind(sessionId, errCode);
        }
        TRANS_LOGI(TRANS_SDK, "ok, sessionid=%{public}d", sessionId);
        return SOFTBUS_OK;
    }
    if (sessionCallback.session.OnSessionOpened != NULL) {
        (void)sessionCallback.session.OnSessionOpened(sessionId, errCode);
    }
    (void)ClientDeleteSession(sessionId);
    TRANS_LOGI(TRANS_SDK, "ok, sessionid=%{public}d", sessionId);
    return SOFTBUS_OK;
}

int32_t TransOnSessionClosed(int32_t channelId, int32_t channelType, ShutdownReason reason)
{
    TRANS_LOGI(TRANS_SDK, "channelId=%{public}d, channelType=%{public}d", channelId, channelType);
    int32_t sessionId = INVALID_SESSION_ID;
    int32_t ret = SOFTBUS_NO_INIT;
    SessionListenerAdapter sessionCallback;
    bool isServer = false;
    bool isUdpType = (channelType == CHANNEL_TYPE_UDP ? true : false);
    (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
    if (isUdpType) {
        (void)GetSocketCallbackAdapterByUdpChannelId(channelId, channelType, &sessionId, &sessionCallback, &isServer);
    } else {
        (void)GetSocketCallbackAdapterByChannelId(channelId, channelType, &sessionId, &sessionCallback, &isServer);
    }
    if (!isServer) {
        SessionInfoReport(sessionId);
    }
    SessionEnableStatus enableStatus = ENABLE_STATUS_INIT;
    (void)ClientGetChannelBySessionId(sessionId, NULL, NULL, &enableStatus);
    TRANS_LOGI(TRANS_SDK, "trigger session close callback");
    if (sessionCallback.isSocketListener && enableStatus == ENABLE_STATUS_SUCCESS) {
        bool isD2D = false;
        (void)ClientGetSessionIsD2DByChannelId(channelId, channelType, &isD2D);
        ISocketListener *listener = NULL;
        if (isD2D) {
            listener = &sessionCallback.socketServer;
        } else {
            listener = isServer ? &sessionCallback.socketServer : &sessionCallback.socketClient;
        }
        if (listener->OnShutdown != NULL) {
            listener->OnShutdown(sessionId, reason);
        }
        ret = ClientDeleteSocketSession(sessionId);
    } else if (sessionCallback.session.OnSessionClosed != NULL) {
        sessionCallback.session.OnSessionClosed(sessionId);
        ret = ClientDeleteSession(sessionId);
    }

    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "client delete session failed");
        return ret;
    }
    TRANS_LOGI(TRANS_SDK, "ok, sessionId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

static int32_t ProcessReceivedFileData(
    int32_t sessionId, int32_t channelId, const char *data, uint32_t len, SessionPktType type)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    int32_t ret = ClientGetSessionDataById(sessionId, sessionName, SESSION_NAME_SIZE_MAX, KEY_SESSION_NAME);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "get sessionName by sessionId=%{public}d failed, ret=%{public}d", sessionId, ret);
        return ret;
    }

    ret = ProcessFileFrameData(sessionId, channelId, data, len, type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "process file frame data failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransOnDataReceived(int32_t channelId, int32_t channelType, const void *data, uint32_t len, SessionPktType type)
{
    int32_t sessionId;
    SessionListenerAdapter sessionCallback;
    bool isServer = false;
    bool isD2D = false;
    (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
    int32_t ret = GetSocketCallbackAdapterByChannelId(channelId, channelType, &sessionId, &sessionCallback, &isServer);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get session callback failed");
    (void)ClientGetSessionIsD2DByChannelId(channelId, channelType, &isD2D);
    (void)ClientResetIdleTimeoutById(sessionId);
    ISocketListener *listener = NULL;
    if (isD2D) {
        listener = &sessionCallback.socketServer;
    } else {
        listener = isServer ? &sessionCallback.socketServer : &sessionCallback.socketClient;
    }
    switch (type) {
        case TRANS_SESSION_BYTES:
            if (sessionCallback.isSocketListener) {
                if (listener->OnBytes != NULL) {
                    listener->OnBytes(sessionId, data, len);
                }
            } else if (sessionCallback.session.OnBytesReceived != NULL) {
                sessionCallback.session.OnBytesReceived(sessionId, data, len);
            }
            break;
        case TRANS_SESSION_MESSAGE:
            if (sessionCallback.isSocketListener) {
                if (listener->OnMessage != NULL) {
                    listener->OnMessage(sessionId, data, len);
                }
            } else if (sessionCallback.session.OnMessageReceived != NULL) {
                sessionCallback.session.OnMessageReceived(sessionId, data, len);
            }
            break;
        case TRANS_SESSION_FILE_FIRST_FRAME:
        case TRANS_SESSION_FILE_ONGOINE_FRAME:
        case TRANS_SESSION_FILE_LAST_FRAME:
        case TRANS_SESSION_FILE_ONLYONE_FRAME:
        case TRANS_SESSION_FILE_ALLFILE_SENT:
        case TRANS_SESSION_FILE_CRC_CHECK_FRAME:
        case TRANS_SESSION_FILE_RESULT_FRAME:
        case TRANS_SESSION_FILE_ACK_REQUEST_SENT:
        case TRANS_SESSION_FILE_ACK_RESPONSE_SENT:
            if (channelType == CHANNEL_TYPE_PROXY) {
                return ProcessReceivedFileData(sessionId, channelId, (char *)data, len, type);
            }
            break;
        default:
            TRANS_LOGE(TRANS_FILE, "revc unknown session type = %{public}d", type);
            return SOFTBUS_TRANS_INVALID_SESSION_TYPE;
    }

    return SOFTBUS_OK;
}

int32_t TransOnOnStreamRecevied(
    int32_t channelId, int32_t channelType, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    int32_t sessionId;
    SessionListenerAdapter sessionCallback;
    bool isServer = false;
    (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
    int32_t ret = GetSocketCallbackAdapterByChannelId(channelId, channelType, &sessionId, &sessionCallback, &isServer);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_STREAM, "get session callback failed");
        return ret;
    }

    (void)ClientResetIdleTimeoutById(sessionId);
    if (sessionCallback.isSocketListener) {
        ISocketListener *listener = isServer ? &sessionCallback.socketServer : &sessionCallback.socketClient;
        if (listener->OnStream != NULL) {
            listener->OnStream(sessionId, data, ext, param);
        }
        return SOFTBUS_OK;
    }

    if (sessionCallback.session.OnStreamReceived == NULL) {
        TRANS_LOGE(TRANS_STREAM, "listener OnStreamReceived is NULL");
        return SOFTBUS_NO_INIT;
    }

    sessionCallback.session.OnStreamReceived(sessionId, data, ext, param);
    return SOFTBUS_OK;
}

int32_t TransOnQosEvent(int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    int32_t sessionId;
    ISessionListener listener = { 0 };
    int32_t ret = GetSessionCallbackByChannelId(channelId, channelType, &sessionId, &listener);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_QOS, "get session callback failed");
        return ret;
    }
    if (listener.OnQosEvent == NULL) {
        TRANS_LOGE(
            TRANS_QOS, "listener OnQosEvent is NULL, channelId=%{public}d, sessionId=%{public}d", channelId, sessionId);
        return SOFTBUS_NO_INIT;
    }
    listener.OnQosEvent(sessionId, eventId, tvCount, tvList);
    return SOFTBUS_OK;
}

int32_t ClientTransOnChannelBind(int32_t channelId, int32_t channelType)
{
    TRANS_LOGI(TRANS_SDK, "channelId=%{public}d, channelType=%{public}d", channelId, channelType);
    int32_t socket = INVALID_SESSION_ID;
    SessionListenerAdapter sessionCallback;
    bool isServer = false;
    (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
    int32_t ret = GetSocketCallbackAdapterByChannelId(channelId, channelType, &socket, &sessionCallback, &isServer);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get session callback failed channelId=%{public}d", channelId);
        return ret;
    }

    if (!sessionCallback.isSocketListener) {
        TRANS_LOGW(TRANS_SDK, "QoS recv session callback channelId=%{public}d", channelId);
        return SOFTBUS_NOT_NEED_UPDATE;
    }

    if (!isServer) {
        TRANS_LOGW(TRANS_SDK, "only server need OnChannelBind channelId=%{public}d", channelId);
        return SOFTBUS_NOT_NEED_UPDATE;
    }

    ISocketListener *listener = &sessionCallback.socketServer;
    char sessionName[SESSION_NAME_SIZE_MAX + 1] = { 0 };
    ret = ClientGetSessionNameByChannelId(channelId, channelType, sessionName, SESSION_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "failed to get sessionName, channelId=%{public}d", channelId);
        return ret;
    }
    bool isContained = CheckNameContainServiceId(sessionName);
    if (!isContained) {
        ret = TransOnBindSuccess(socket, listener);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "client on bind failed channelId=%{public}d", channelId);
            return ret;
        }
    } else {
        ret = TransOnServiceBindSuccess(socket, listener);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "client on service bind failed channelId=%{public}d", channelId);
            return ret;
        }
    }
    TRANS_LOGI(TRANS_SDK, "ok, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

int32_t ClientTransIfChannelForSocket(const char *sessionName, bool *isSocket)
{
    if (sessionName == NULL || isSocket == NULL) {
        TRANS_LOGE(TRANS_SDK, "sessionName or isSocket is NULL");
        return SOFTBUS_INVALID_PARAM;
    }

    SessionListenerAdapter sessionCallback;
    (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
    int32_t ret = ClientGetSessionCallbackAdapterByName(sessionName, &sessionCallback);
    if (ret != SOFTBUS_OK) {
        char *tmpName = NULL;
        Anonymize(sessionName, &tmpName);
        TRANS_LOGE(TRANS_SDK, "get session callback failed, sessionName=%{public}s", AnonymizeWrapper(tmpName));
        AnonymizeFree(tmpName);
        return ret;
    }

    *isSocket = sessionCallback.isSocketListener;
    return SOFTBUS_OK;
}

int32_t ClientTransOnQos(int32_t channelId, int32_t channelType, QoSEvent event, const QosTV *qos, uint32_t count)
{
    if (qos == NULL) {
        TRANS_LOGE(TRANS_SDK, "qos is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t socket = INVALID_SESSION_ID;
    SessionListenerAdapter sessionCallback;
    bool isServer = false;
    (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
    int32_t ret = GetSocketCallbackAdapterByChannelId(channelId, channelType, &socket, &sessionCallback, &isServer);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get session callback failed channelId=%{public}d", channelId);
        return ret;
    }
    if (isServer) {
        TRANS_LOGI(TRANS_SDK, "not report qos event on server side");
        return SOFTBUS_OK;
    }
    if (!sessionCallback.isSocketListener) {
        TRANS_LOGI(TRANS_SDK, "not report qos event on non-socket session");
        return SOFTBUS_OK;
    }
    if (sessionCallback.socketClient.OnQos == NULL) {
        TRANS_LOGD(TRANS_SDK, "listener OnQos is NULL, sessionId=%{public}d", socket);
        return SOFTBUS_OK;
    }
    ret = ClientCacheQosEvent(socket, event, qos, count);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_TRANS_NO_NEED_CACHE_QOS_EVENT) {
        TRANS_LOGE(TRANS_SDK, "cache qos event failed, ret=%{public}d", ret);
        return ret;
    } else if (ret == SOFTBUS_TRANS_NO_NEED_CACHE_QOS_EVENT) {
        sessionCallback.socketClient.OnQos(socket, event, qos, count);
        TRANS_LOGI(TRANS_SDK, "report qos event to client socket=%{public}d, event=%{public}d", socket, event);
    }
    return SOFTBUS_OK;
}

int32_t ClientTransOnEvent(
    int32_t channelId, int32_t channelType, SocketEventType event, const void *eventData, uint32_t dataLen)
{
    if (eventData == NULL) {
        TRANS_LOGE(TRANS_SDK, "eventData is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t socket = INVALID_SESSION_ID;
    SessionListenerAdapter sessionCallback;
    bool isServer = false;
    (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
    int32_t ret = GetSocketCallbackAdapterByChannelId(channelId, channelType, &socket, &sessionCallback, &isServer);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get session callback failed channeId=%{public}d", channelId);
        return ret;
    }
    if (!sessionCallback.isSocketListener) {
        TRANS_LOGI(TRANS_SDK, "not report on event on non-socket session");
        return SOFTBUS_OK;
    }
    ISocketListener *listener = isServer ? &sessionCallback.socketServer : &sessionCallback.socketClient;

    if (listener->OnEvent == NULL) {
        TRANS_LOGD(TRANS_SDK, "listener OnEvent is NULL, sessionId=%{public}d", socket);
        return SOFTBUS_OK;
    }
    listener->OnEvent(socket, event, eventData, dataLen);
    TRANS_LOGI(TRANS_SDK, "report on event to client socket=%{public}d, event=%{public}d", socket, event);
    return SOFTBUS_OK;
}

IClientSessionCallBack *GetClientSessionCb(void)
{
    g_sessionCb.OnSessionOpened = TransOnSessionOpened;
    g_sessionCb.OnSessionClosed = TransOnSessionClosed;
    g_sessionCb.OnSessionOpenFailed = TransOnSessionOpenFailed;
    g_sessionCb.OnDataReceived = TransOnDataReceived;
    g_sessionCb.OnStreamReceived = TransOnOnStreamRecevied;
    g_sessionCb.OnGetSessionId = ClientGetSessionIdByChannelId;
    g_sessionCb.OnQosEvent = TransOnQosEvent;
    g_sessionCb.OnIdleTimeoutReset = ClientResetIdleTimeoutById;
    g_sessionCb.OnRawStreamEncryptDefOptGet = ClientRawStreamEncryptDefOptGet;
    g_sessionCb.OnRawStreamEncryptOptGet = ClientRawStreamEncryptOptGet;
    g_sessionCb.OnChannelBind = ClientTransOnChannelBind;
    g_sessionCb.IfChannelForSocket = ClientTransIfChannelForSocket;
    g_sessionCb.OnQos = ClientTransOnQos;
    g_sessionCb.OnEvent = ClientTransOnEvent;
    return &g_sessionCb;
}
