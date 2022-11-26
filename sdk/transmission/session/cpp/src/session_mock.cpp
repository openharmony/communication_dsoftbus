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

#include "session_mock.h"

#include "client_trans_session_manager.h"
#include "client_trans_session_service.h"
#include "session.h"
#include "session_callback_mock.h"

static ISessionListener g_innerSessionListener = {
    .OnSessionOpened = InnerOnSessionOpened,
    .OnSessionClosed = InnerOnSessionClosed,
    .OnBytesReceived = InnerOnBytesReceived,
    .OnMessageReceived = InnerOnMessageReceived,
};

int CreateSessionServerInner(const char *pkgName, const char *sessionName)
{
    return CreateSessionServer(pkgName, sessionName, &g_innerSessionListener);
}

int RemoveSessionServerInner(const char *pkgName, const char *sessionName)
{
    return RemoveSessionServer(pkgName, sessionName);
}

int OpenSessionInner(const char *mySessionName, const char *peerSessionName, const char *peerNetworkId,
    const char *groupId, int flag)
{
    SessionAttribute attr = {flag};
    return OpenSessionSync(mySessionName, peerSessionName, peerNetworkId, groupId, &attr);
}

void CloseSessionInner(int sessionId)
{
    return CloseSession(sessionId);
}

int32_t GrantPermissionInner(int uid, int pid, const char *busName)
{
    return ClientGrantPermission(uid, pid, busName);
}

int32_t RemovePermissionInner(const char *busName)
{
    return ClientRemovePermission(busName);
}

int32_t SendBytesInner(int32_t sessionId, const void *data, uint32_t len)
{
    return SendBytes(sessionId, data, len);
}

int32_t GetPeerUidInner(int32_t sessionId, int *data)
{
    return ClientGetSessionIntegerDataById(sessionId, data, KEY_PEER_UID);
}

int32_t GetPeerPidInner(int32_t sessionId, int *data)
{
    return ClientGetSessionIntegerDataById(sessionId, data, KEY_PEER_PID);
}

int32_t IsServerSideInner(int32_t sessionId, int *data)
{
    return ClientGetSessionIntegerDataById(sessionId, data, KEY_IS_SERVER);
}

int32_t GetMySessionNameInner(int32_t sessionId, char *data, uint16_t len)
{
    return ClientGetSessionDataById(sessionId, data, len, KEY_SESSION_NAME);
}

int32_t GetPeerSessionNameInner(int32_t sessionId, char *data, uint16_t len)
{
    return ClientGetSessionDataById(sessionId, data, len, KEY_PEER_SESSION_NAME);
}

int32_t GetPeerDeviceIdInner(int32_t sessionId, char *data, uint16_t len)
{
    return ClientGetSessionDataById(sessionId, data, len, KEY_PEER_DEVICE_ID);
}

int32_t GetPkgNameInner(int32_t sessionId, char *data, uint16_t len)
{
    return ClientGetSessionDataById(sessionId, data, len, KEY_PKG_NAME);
}
