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

#include "client_trans_session_callback.h"

#include <securec.h>

#include "client_trans_session_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static IClientSessionCallBack g_sessionCb;

static int32_t AcceptSessionAsServer(const char *sessionName, const ChannelInfo *channel, uint32_t flag,
    int32_t *sessionId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "AcceptSessionAsServer");
    SessionInfo *session = (SessionInfo *)SoftBusCalloc(sizeof(SessionInfo));
    if (session == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc failed");
        return SOFTBUS_MALLOC_ERR;
    }

    session->channelId = channel->channelId;
    session->channelType = channel->channelType;
    session->peerPid = channel->peerPid;
    session->peerUid = channel->peerUid;
    session->isServer = channel->isServer;
    session->isEnable = true;
    session->info.flag = flag;
    if (strcpy_s(session->info.peerSessionName, SESSION_NAME_SIZE_MAX, channel->peerSessionName) != EOK ||
        strcpy_s(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX, channel->peerDeviceId) != EOK ||
        strcpy_s(session->info.groupId, GROUP_ID_SIZE_MAX, channel->groupId) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "client add peer session name, device id, group id failed");
        SoftBusFree(session);
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = ClientAddNewSession(sessionName, session);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "client add session failed");
        SoftBusFree(session);
        return SOFTBUS_ERR;
    }
    *sessionId = session->sessionId;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "AcceptSessionAsServer ok");
    return SOFTBUS_OK;
}

static int32_t GetSessionCallbackByChannelId(int32_t channelId, int32_t channelType,
    int32_t *sessionId, ISessionListener *listener)
{
    if ((channelId < 0) || (sessionId == NULL) || (listener == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ClientGetSessionIdByChannelId(channelId, channelType, sessionId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get sessionId failed, channelId [%d]", channelId);
        return SOFTBUS_ERR;
    }
    ret = ClientGetSessionCallbackById(*sessionId, listener);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get session listener failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransOnSessionOpened(const char *sessionName, const ChannelInfo *channel, uint32_t flag)
{
    if ((sessionName == NULL) || (channel == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransOnSessionOpened: sessionName=%s, flag=%d, isServer=%d",
        sessionName, flag, channel->isServer);

    ISessionListener listener = {0};
    int32_t ret = ClientGetSessionCallbackByName(sessionName, &listener);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get session listener failed");
        return SOFTBUS_ERR;
    }

    int32_t sessionId = INVALID_SESSION_ID;
    if (channel->isServer) {
        ret = AcceptSessionAsServer(sessionName, channel, flag, &sessionId);
    } else {
        ret = ClientEnableSessionByChannelId(channel, &sessionId);
    }

    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "accept session failed");
        return SOFTBUS_ERR;
    }

    if ((listener.OnSessionOpened == NULL) || (listener.OnSessionOpened(sessionId, SOFTBUS_OK) != SOFTBUS_OK)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OnSessionOpened failed");
        (void)ClientDeleteSession(sessionId);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransOnSessionOpened ok");
    return SOFTBUS_OK;
}

int32_t TransOnSessionOpenFailed(int32_t channelId, int32_t channelType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransOnSessionOpenFailed: channelId=%d, channelType=%d",
        channelId, channelType);
    int32_t sessionId;
    ISessionListener listener = {0};
    int32_t ret = GetSessionCallbackByChannelId(channelId, channelType, &sessionId, &listener);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get session callback failed");
        return ret;
    }

    if (listener.OnSessionOpened != NULL) {
        (void)listener.OnSessionOpened(sessionId, SOFTBUS_ERR);
    }

    (void)ClientDeleteSession(sessionId);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransOnSessionOpenFailed ok");
    return SOFTBUS_OK;
}

int32_t TransOnSessionClosed(int32_t channelId, int32_t channelType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransOnSessionClosed: channelId=%d, channelType=%d",
        channelId, channelType);
    int32_t sessionId;
    ISessionListener listener = {0};
    int32_t ret = GetSessionCallbackByChannelId(channelId, channelType, &sessionId, &listener);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get session callback failed");
        return ret;
    }

    if (listener.OnSessionClosed != NULL) {
        listener.OnSessionClosed(sessionId);
    }

    ret = ClientDeleteSession(sessionId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "client delete session failed");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransOnSessionClosed ok");
    return SOFTBUS_OK;
}

int32_t TransOnDataReceived(int32_t channelId, int32_t channelType,
    const void *data, uint32_t len, SessionPktType type)
{
    int32_t sessionId;
    ISessionListener listener = {0};
    int32_t ret = GetSessionCallbackByChannelId(channelId, channelType, &sessionId, &listener);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get session callback failed");
        return ret;
    }

    switch (type) {
        case TRANS_SESSION_BYTES:
            if (listener.OnBytesReceived != NULL) {
                listener.OnBytesReceived(sessionId, data, len);
            }
            break;
        case TRANS_SESSION_MESSAGE:
            if (listener.OnMessageReceived != NULL) {
                listener.OnMessageReceived(sessionId, data, len);
            }
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unknown session type");
            return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t TransOnOnStreamRecevied(int32_t channelId, int32_t channelType,
    const StreamData *data, const StreamData *ext, const FrameInfo *param)
{
    int32_t sessionId;
    ISessionListener listener = {0};
    int32_t ret = GetSessionCallbackByChannelId(channelId, channelType, &sessionId, &listener);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get session callback failed");
        return ret;
    }
    if (listener.OnStreamReceived == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "listener OnStreamReceived is NULL");
        return SOFTBUS_ERR;
    }
    listener.OnStreamReceived(sessionId, data, ext, param);
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
    return &g_sessionCb;
}
