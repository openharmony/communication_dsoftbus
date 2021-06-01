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

#ifndef CLIENT_TRANS_SESSION_MANAGER_H
#define CLIENT_TRANS_SESSION_MANAGER_H

#include "session.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char peerSessionName[SESSION_NAME_SIZE_MAX];
    char peerDeviceId[DEVICE_ID_SIZE_MAX];
    char groupId[GROUP_ID_SIZE_MAX];
    uint32_t flag; // TYPE_MESSAGE & TYPE_BYTES & TYPE_FILE
} SessionTag;

typedef struct {
    ListNode node;
    uint16_t timeout;
    int32_t sessionId;
    int32_t channelId;
    ChannelType channelType;
    SessionTag info;
    bool isServer;
    int32_t peerUid;
    int32_t peerPid;
} SessionInfo;

typedef struct {
    ListNode node;
    SoftBusSecType type;
    char sessionName[SESSION_NAME_SIZE_MAX];
    char pkgName[PKG_NAME_SIZE_MAX];
    union {
        ISessionListener session;
    } listener;
    ListNode sessionList;
} ClientSessionServer;

typedef struct {
    const char *sessionName;
    const char *peerSessionName;
    const char *peerDeviceId;
    const char *groupId;
    const SessionAttribute* attr;
} SessionParam;

typedef enum {
    KEY_SESSION_NAME = 1,
    KEY_PEER_SESSION_NAME,
    KEY_PEER_DEVICE_ID,
    KEY_IS_SERVER,
    KEY_PEER_PID,
    KEY_PEER_UID,
} SessionKey;

int32_t ClientAddNewSession(const char* sessionName, SessionInfo* session);

/**
 * @brief Add session.
 * @return  if session already added, return SOFTBUS_TRANS_SESSION_REPEATED, else return SOFTBUS_OK or SOFTBUS_ERR.
 */
int32_t ClientAddSession(const SessionParam* param, int32_t* sessionId, bool* isEnabled);

int32_t ClientDeleteSessionServer(SoftBusSecType type, const char* sessionName);

int32_t ClientDeleteSession(int32_t sessionId);

int32_t ClientGetSessionDataById(int32_t sessionId, char* data, uint16_t len, SessionKey key);

int32_t ClientGetSessionIntegerDataById(int32_t sessionId, int *data, SessionKey key);

int32_t ClientGetChannelBySessionId(int32_t sessionId, int32_t* channelId, int32_t* type);

int32_t ClientSetChannelBySessionId(int32_t sessionId, int32_t channelId);

int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t* sessionId);

int32_t ClientEnableSessionByChannelId(const ChannelInfo *channel, int32_t* sessionId);

int32_t ClientGetSessionCallbackById(int32_t sessionId, ISessionListener* callback);

int32_t ClientGetSessionCallbackByName(const char* sessionName, ISessionListener* callback);

int32_t ClientAddSessionServer(SoftBusSecType type, const char* pkgName, const char* sessionName,
    const ISessionListener* listener);

#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_SESSION_MANAGER_H