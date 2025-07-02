/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "trans_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

void *g_managerInterface = nullptr;

TransMgrInterfaceMock::TransMgrInterfaceMock()
{
    g_managerInterface = reinterpret_cast<void *>(this);
}

TransMgrInterfaceMock::~TransMgrInterfaceMock()
{
    g_managerInterface = nullptr;
}

static TransManagerInterface *GetManagerInterface()
{
    return reinterpret_cast<TransManagerInterface *>(g_managerInterface);
}

int32_t TransMgrInterfaceMock::ActionOfClientGetDataConfigByChannelId(
    int32_t channelId, int32_t channelType, uint32_t *dataConfig)
{
    (void)channelId;
    (void)channelType;
    *dataConfig = 1;
    return SOFTBUS_OK;
}

int32_t TransMgrInterfaceMock::ActionOfClientGetSessionIsAsyncBySessionId(int32_t sessionId, bool *isAsync)
{
    (void)sessionId;
    *isAsync = false;
    return SOFTBUS_OK;
}

int32_t TransMgrInterfaceMock::ActionOfGetSocketLifecycleAndSessionNameBySessionId(
    int32_t sessionId, char *sessionName, SocketLifecycleData *lifecycle)
{
    (void)sessionId;
    (void)sessionName;
    lifecycle->sessionState = SESSION_STATE_CANCELLING;
    lifecycle->bindErrCode = SOFTBUS_STRCPY_ERR;
    return SOFTBUS_OK;
}

#ifdef __cplusplus
extern "C" {
#endif

int32_t ClientGetDataConfigByChannelId(int32_t channelId, int32_t channelType, uint32_t *dataConfig)
{
    return GetManagerInterface()->ClientGetDataConfigByChannelId(channelId, channelType, dataConfig);
}

int32_t ClientGetSessionIsAsyncBySessionId(int32_t sessionId, bool *isAsync)
{
    return GetManagerInterface()->ClientGetSessionIsAsyncBySessionId(sessionId, isAsync);
}

int32_t GetSocketLifecycleAndSessionNameBySessionId(
    int32_t sessionId, char *sessionName, SocketLifecycleData *lifecycle)
{
    return GetManagerInterface()->GetSocketLifecycleAndSessionNameBySessionId(sessionId, sessionName, lifecycle);
}

int32_t ClientHandleBindWaitTimer(int32_t socket, uint32_t maxWaitTime, TimerAction action)
{
    return GetManagerInterface()->ClientHandleBindWaitTimer(socket, maxWaitTime, action);
}

int32_t SetSessionStateBySessionId(int32_t sessionId, SessionState sessionState, int32_t optional)
{
    return GetManagerInterface()->SetSessionStateBySessionId(sessionId, sessionState, optional);
}

int32_t ClientSignalSyncBind(int32_t socket, int32_t errCode)
{
    return GetManagerInterface()->ClientSignalSyncBind(socket, errCode);
}

int32_t ClientGetPeerSocketInfoById(int32_t socket, PeerSocketInfo *peerSocketInfo)
{
    return GetManagerInterface()->ClientGetPeerSocketInfoById(socket, peerSocketInfo);
}

int32_t ClientDeleteSocketSession(int32_t sessionId)
{
    return GetManagerInterface()->ClientDeleteSocketSession(sessionId);
}

int32_t GetIsAsyncAndTokenTypeBySessionId(int32_t sessionId, bool *isAsync, int32_t *tokenType)
{
    return GetManagerInterface()->GetIsAsyncAndTokenTypeBySessionId(sessionId, isAsync, tokenType);
}

int32_t ClientGetCachedQosEventBySocket(int32_t socket, CachedQosEvent *cachedQosEvent)
{
    return GetManagerInterface()->ClientGetCachedQosEventBySocket(socket, cachedQosEvent);
}

int32_t ClientDeleteSession(int32_t sessionId)
{
    return GetManagerInterface()->ClientDeleteSession(sessionId);
}

int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing)
{
    return GetManagerInterface()->ClientGetSessionIdByChannelId(channelId, channelType, sessionId, isClosing);
}

int32_t ClientGetSessionCallbackAdapterById(int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer)
{
    return GetManagerInterface()->ClientGetSessionCallbackAdapterById(sessionId, callbackAdapter, isServer);
}

int32_t ClientSetEnableStatusBySocket(int32_t socket, SessionEnableStatus enableStatus)
{
    return GetManagerInterface()->ClientSetEnableStatusBySocket(socket, enableStatus);
}

int32_t ClientGetChannelBySessionId(
    int32_t sessionId, int32_t *channelId, int32_t *type, SessionEnableStatus *enableStatus)
{
    return GetManagerInterface()->ClientGetChannelBySessionId(sessionId, channelId, type, enableStatus);
}

int32_t ClientResetIdleTimeoutById(int32_t sessionId)
{
    return GetManagerInterface()->ClientResetIdleTimeoutById(sessionId);
}

int32_t ClientGetSessionDataById(int32_t sessionId, char *data, uint16_t len, TransSessionKey key)
{
    return GetManagerInterface()->ClientGetSessionDataById(sessionId, data, len, key);
}

int32_t ProcessFileFrameData(int32_t sessionId, int32_t channelId, const char *data, uint32_t len, int32_t type)
{
    return GetManagerInterface()->ProcessFileFrameData(sessionId, channelId, data, len, type);
}
#ifdef __cplusplus
}
#endif
}
