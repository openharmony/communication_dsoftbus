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

#ifndef TRANS_MANAGER_MOCK_H
#define TRANS_MANAGER_MOCK_H

#include <gmock/gmock.h>

#include "softbus_error_code.h"
#include "client_trans_session_manager_struct.h"

namespace OHOS {
class TransManagerInterface {
public:
    TransManagerInterface() {};
    virtual ~TransManagerInterface() {};

    virtual int32_t ClientGetDataConfigByChannelId(int32_t channelId, int32_t channelType, uint32_t *dataConfig) = 0;
    virtual int32_t ClientGetSessionIsAsyncBySessionId(int32_t sessionId, bool *isAsync) = 0;
    virtual int32_t GetSocketLifecycleAndSessionNameBySessionId(
        int32_t sessionId, char *sessionName, SocketLifecycleData *lifecycle) = 0;
    virtual int32_t ClientHandleBindWaitTimer(int32_t socket, uint32_t maxWaitTime, TimerAction action) = 0;
    virtual int32_t SetSessionStateBySessionId(int32_t sessionId, SessionState sessionState, int32_t optional) = 0;
    virtual int32_t ClientSignalSyncBind(int32_t socket, int32_t errCode) = 0;
    virtual int32_t ClientGetPeerSocketInfoById(int32_t socket, PeerSocketInfo *peerSocketInfo) = 0;
    virtual int32_t ClientDeleteSocketSession(int32_t sessionId) = 0;
    virtual int32_t GetIsAsyncAndTokenTypeBySessionId(int32_t sessionId, bool *isAsync, int32_t *tokenType) = 0;
    virtual int32_t ClientGetCachedQosEventBySocket(int32_t socket, CachedQosEvent *cachedQosEvent) = 0;
    virtual int32_t ClientDeleteSession(int32_t sessionId) = 0;
    virtual int32_t ClientGetSessionIdByChannelId(
        int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing) = 0;
    virtual int32_t ClientGetSessionCallbackAdapterById(
        int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer) = 0;
    virtual int32_t ClientSetEnableStatusBySocket(int32_t socket, SessionEnableStatus enableStatus) = 0;
    virtual int32_t ClientGetChannelBySessionId(
        int32_t sessionId, int32_t *channelId, int32_t *type, SessionEnableStatus *enableStatus) = 0;
    virtual int32_t ClientResetIdleTimeoutById(int32_t sessionId) = 0;
    virtual int32_t ClientGetSessionDataById(int32_t sessionId, char *data, uint16_t len, TransSessionKey key) = 0;
    virtual int32_t ProcessFileFrameData(
        int32_t sessionId, int32_t channelId, const char *data, uint32_t len, int32_t type) = 0;
};

class TransMgrInterfaceMock : public TransManagerInterface {
public:
    TransMgrInterfaceMock();
    ~TransMgrInterfaceMock() override;

    MOCK_METHOD3(ClientGetDataConfigByChannelId, int32_t(
        int32_t channelId, int32_t channelType, uint32_t *dataConfig));
    MOCK_METHOD2(ClientGetSessionIsAsyncBySessionId, int32_t(int32_t sessionId, bool *isAsync));
    MOCK_METHOD3(GetSocketLifecycleAndSessionNameBySessionId, int32_t(
        int32_t sessionId, char *sessionName, SocketLifecycleData *lifecycle));
    MOCK_METHOD3(ClientHandleBindWaitTimer, int32_t(int32_t socket, uint32_t maxWaitTime, TimerAction action));
    MOCK_METHOD3(SetSessionStateBySessionId, int32_t(int32_t sessionId, SessionState sessionState, int32_t optional));
    MOCK_METHOD2(ClientSignalSyncBind, int32_t(int32_t socket, int32_t errCode));
    MOCK_METHOD2(ClientGetPeerSocketInfoById, int32_t(int32_t socket, PeerSocketInfo *peerSocketInfo));
    MOCK_METHOD1(ClientDeleteSocketSession, int32_t(int32_t sessionId));
    MOCK_METHOD3(GetIsAsyncAndTokenTypeBySessionId, int32_t(int32_t sessionId, bool *isAsync, int32_t *tokenType));
    MOCK_METHOD2(ClientGetCachedQosEventBySocket, int32_t(int32_t socket, CachedQosEvent *cachedQosEvent));
    MOCK_METHOD1(ClientDeleteSession, int32_t(int32_t sessionId));
    MOCK_METHOD4(ClientGetSessionIdByChannelId, int32_t(
        int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing));
    MOCK_METHOD3(ClientGetSessionCallbackAdapterById, int32_t(
        int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer));
    MOCK_METHOD2(ClientSetEnableStatusBySocket, int32_t(int32_t socket, SessionEnableStatus enableStatus));
    MOCK_METHOD4(ClientGetChannelBySessionId, int32_t(
        int32_t sessionId, int32_t *channelId, int32_t *type, SessionEnableStatus *enableStatus));
    MOCK_METHOD1(ClientResetIdleTimeoutById, int32_t(int32_t sessionId));
    MOCK_METHOD4(ClientGetSessionDataById, int32_t(int32_t sessionId, char *data, uint16_t len, TransSessionKey key));
    MOCK_METHOD5(ProcessFileFrameData, int32_t(
        int32_t sessionId, int32_t channelId, const char *data, uint32_t len, int32_t type));

    static int32_t ActionOfClientGetDataConfigByChannelId(
        int32_t channelId, int32_t channelType, uint32_t *dataConfig);
    static int32_t ActionOfClientGetSessionIsAsyncBySessionId(int32_t sessionId, bool *isAsync);
    static int32_t ActionOfGetSocketLifecycleAndSessionNameBySessionId(
        int32_t sessionId, char *sessionName, SocketLifecycleData *lifecycle);
};

} // namespace OHOS
#endif // TRANS_MANAGER_MOCK_H
