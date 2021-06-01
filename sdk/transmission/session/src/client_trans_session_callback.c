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
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"

static int32_t AcceptSessionAsServer(const char *sessionName, const ChannelInfo *channel, uint32_t flag,
    int32_t *sessionId)
{
    SessionInfo *session = (SessionInfo *)SoftBusCalloc(sizeof(SessionInfo));
    if (session == NULL) {
        LOG_ERR("malloc failed");
        return SOFTBUS_MALLOC_ERR;
    }

    session->channelId = channel->channelId;
    session->channelType = channel->channelType;
    session->peerPid = channel->peerPid;
    session->peerUid = channel->peerUid;
    session->isServer = channel->isServer;
    session->info.flag = flag;
    if (strcpy_s(session->info.peerSessionName, SESSION_NAME_SIZE_MAX, channel->peerSessionName) != EOK ||
        strcpy_s(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX, channel->peerDeviceId) != EOK ||
        strcpy_s(session->info.groupId, GROUP_ID_SIZE_MAX, channel->groupId) != EOK) {
        LOG_ERR("client add peer session name or device id or group id failed");
        SoftBusFree(session);
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = ClientAddNewSession(sessionName, session);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("client add session failed");
        SoftBusFree(session);
        return SOFTBUS_ERR;
    }
    *sessionId = session->sessionId;
    return SOFTBUS_OK;
}

static int32_t GetSessionCallbackByChannelId(int32_t channelId, int32_t *sessionId, ISessionListener *listener)
{
    if ((channelId < 0) || (sessionId == NULL) || (listener == NULL)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ClientGetSessionIdByChannelId(channelId, sessionId);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get sessionId failed, channelId [%d]", channelId);
        return SOFTBUS_ERR;
    }
    ret = ClientGetSessionCallbackById(*sessionId, listener);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get session listener failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransOnSessionOpened(const char *sessionName, const ChannelInfo *channel, uint32_t flag)
{
    if ((sessionName == NULL) || (channel == NULL)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    ISessionListener listener = {0};
    int32_t ret = ClientGetSessionCallbackByName(sessionName, &listener);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get session listener failed");
        return SOFTBUS_ERR;
    }

    int32_t sessionId = INVALID_SESSION_ID;
    if (channel->isServer) {
        ret = AcceptSessionAsServer(sessionName, channel, flag, &sessionId);
    } else {
        ret = ClientEnableSessionByChannelId(channel, &sessionId);
    }

    if (ret != SOFTBUS_OK) {
        LOG_ERR("accept session failed");
        return SOFTBUS_ERR;
    }

    if ((listener.OnSessionOpened == NULL) || (listener.OnSessionOpened(sessionId, SOFTBUS_OK) != SOFTBUS_OK)) {
        LOG_ERR("OnSessionOpened failed");
        (void)ClientDeleteSession(sessionId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransOnSessionOpenFailed(int32_t channelId)
{
    int32_t sessionId;
    ISessionListener listener = {0};
    int32_t ret = GetSessionCallbackByChannelId(channelId, &sessionId, &listener);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get session callback failed");
        return ret;
    }

    if (listener.OnSessionOpened != NULL) {
        (void)listener.OnSessionOpened(sessionId, SOFTBUS_ERR);
    }

    (void)ClientDeleteSession(sessionId);
    return SOFTBUS_OK;
}

int32_t TransOnSessionClosed(int32_t channelId)
{
    int32_t sessionId;
    ISessionListener listener = {0};
    int32_t ret = GetSessionCallbackByChannelId(channelId, &sessionId, &listener);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get session callback failed");
        return ret;
    }

    if (listener.OnSessionClosed != NULL) {
        listener.OnSessionClosed(sessionId);
    }

    ret = ClientDeleteSession(sessionId);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("client delete session failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransOnDataReceived(int32_t channelId, const void *data, uint32_t len, SessionPktType type)
{
    int32_t sessionId;
    ISessionListener listener = {0};
    int32_t ret = GetSessionCallbackByChannelId(channelId, &sessionId, &listener);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get session callback failed");
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
            LOG_ERR("unknown session type");
            return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}