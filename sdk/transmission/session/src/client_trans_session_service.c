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

#include "client_trans_session_service.h"

#include <securec.h>

#include "client_trans_channel_manager.h"
#include "client_trans_session_manager.h"
#include "softbus_client_frame_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"
#include "softbus_utils.h"

static bool IsValidSessionId(int sessionId)
{
    if ((sessionId < 0) || (sessionId > MAX_SESSION_ID)) {
        LOG_ERR("invalid sessionId [%d]", sessionId);
        return false;
    }
    return true;
}

static bool IsValidListener(const ISessionListener *listener)
{
    if ((listener != NULL) &&
        (listener->OnSessionOpened != NULL) &&
        (listener->OnSessionClosed != NULL) &&
        (listener->OnBytesReceived != NULL) &&
        (listener->OnMessageReceived != NULL)) {
        return true;
    }
    LOG_ERR("invalid ISessionListener");
    return false;
}

static int32_t OpenSessionWithExistSession(int32_t sessionId, bool isEnabled)
{
    if (!isEnabled) {
        LOG_INFO("the channel is opening");
        return sessionId;
    }

    ISessionListener listener = {0};
    if (ClientGetSessionCallbackById(sessionId, &listener) != SOFTBUS_OK) {
        LOG_ERR("get session listener failed");
        return sessionId;
    }

    if ((listener.OnSessionOpened == NULL) || (listener.OnSessionOpened(sessionId, SOFTBUS_OK) != 0)) {
        LOG_ERR("session callback OnSessionOpened failed");
        CloseSession(sessionId);
        return INVALID_SESSION_ID;
    }
    return sessionId;
}

int CreateSessionServer(const char *pkgName, const char *sessionName, const ISessionListener *listener)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidListener(listener)) {
        LOG_ERR("invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("init softbus err");
        return SOFTBUS_ERR;
    }

    int ret = ClientAddSessionServer(SEC_TYPE_CIPHERTEXT, pkgName, sessionName, listener);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("add session server err");
        return ret;
    }

    ret = GetServerProvideInterface()->createSessionServer(pkgName, sessionName);
    if (ret == SOFTBUS_SERVER_NAME_REPEATED) {
        LOG_ERR("SessionServer is already created");
    } else if (ret != SOFTBUS_OK) {
        LOG_ERR("Server createSessionServer failed");
        (void)ClientDeleteSessionServer(SEC_TYPE_CIPHERTEXT, sessionName);
    }
    return ret;
}

int RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX)) {
        LOG_ERR("invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = GetServerProvideInterface()->removeSessionServer(pkgName, sessionName);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("remove in server failed");
        return ret;
    }

    ret = ClientDeleteSessionServer(SEC_TYPE_CIPHERTEXT, sessionName);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("delete session server [%s] failed", sessionName);
    }
    return ret;
}

static int32_t CheckParamIsValid(const char *mySessionName, const char *peerSessionName,
    const char *peerDeviceId, const char *groupId, const SessionAttribute *attr)
{
    if (!IsValidString(mySessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerSessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerDeviceId, DEVICE_ID_SIZE_MAX) ||
        !IsValidString(groupId, GROUP_ID_SIZE_MAX) ||
        (attr == NULL) ||
        (attr->dataType >= TYPE_BUTT)) {
        LOG_ERR("invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (strcmp(mySessionName, peerSessionName) != 0) {
        LOG_ERR("session name not same");
        return SOFTBUS_TRANS_INVALID_SESSION_NAME;
    }

    return SOFTBUS_OK;
}

int OpenSession(const char *mySessionName, const char *peerSessionName, const char *peerDeviceId,
    const char *groupId, const SessionAttribute *attr)
{
    int ret = CheckParamIsValid(mySessionName, peerSessionName, peerDeviceId, groupId, attr);
    if (ret != SOFTBUS_OK) {
        return INVALID_SESSION_ID;
    }

    SessionParam param = {
        .sessionName = mySessionName,
        .peerSessionName = peerSessionName,
        .peerDeviceId = peerDeviceId,
        .groupId = groupId,
        .attr = attr,
    };

    int32_t sessionId = INVALID_SESSION_ID;
    bool isEnabled = false;

    ret = ClientAddSession(&param, &sessionId, &isEnabled);
    if (ret != SOFTBUS_OK) {
        if (ret == SOFTBUS_TRANS_SESSION_REPEATED) {
            LOG_INFO("session already opened");
            return OpenSessionWithExistSession(sessionId, isEnabled);
        }
        LOG_ERR("client open session failed, ret [%d]", ret);
        return ret;
    }

    int32_t channelId = GetServerProvideInterface()->openSession(mySessionName, peerSessionName,
        peerDeviceId, groupId, (int32_t)attr->dataType);
    ret = ClientSetChannelBySessionId(sessionId, channelId);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("open session failed");
        (void)ClientDeleteSession(sessionId);
        return INVALID_SESSION_ID;
    }
    LOG_INFO("OpenSession channelId [%d]", channelId);
    return sessionId;
}

void CloseSession(int sessionId)
{
    if (!IsValidSessionId(sessionId)) {
        LOG_ERR("invalid param");
        return;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;

    int32_t ret = ClientGetChannelBySessionId(sessionId, &channelId, &type);
    if (ret == SOFTBUS_OK) {
        LOG_INFO("get channel Id [%d], channel type [%d]", channelId, type);
        (void)ClientTransCloseChannel(channelId, type);
    }

    ISessionListener listener = {0};
    ret = ClientGetSessionCallbackById(sessionId, &listener);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get session listener failed");
    }

    if (listener.OnSessionClosed != NULL) {
        listener.OnSessionClosed(sessionId);
    }

    ClientDeleteSession(sessionId);
    return;
}

int GetMySessionName(int sessionId, char *sessionName, unsigned int len)
{
    if (!IsValidSessionId(sessionId) || (sessionName == NULL) || (len > SESSION_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PARAM;
    }

    return ClientGetSessionDataById(sessionId, sessionName, len, KEY_SESSION_NAME);
}

int GetPeerSessionName(int sessionId, char *sessionName, unsigned int len)
{
    if (!IsValidSessionId(sessionId) || (sessionName == NULL) || (len > SESSION_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PARAM;
    }

    return ClientGetSessionDataById(sessionId, sessionName, len, KEY_PEER_SESSION_NAME);
}

int GetPeerDeviceId(int sessionId, char *devId, unsigned int len)
{
    if (!IsValidSessionId(sessionId) || (devId == NULL) || (len > SESSION_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PARAM;
    }

    return ClientGetSessionDataById(sessionId, devId, len, KEY_PEER_DEVICE_ID);
}
