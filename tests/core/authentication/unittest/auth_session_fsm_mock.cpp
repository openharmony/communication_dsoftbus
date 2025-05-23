/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "auth_session_fsm_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authSessionFsmInterface;
AuthSessionFsmInterfaceMock::AuthSessionFsmInterfaceMock()
{
    g_authSessionFsmInterface = reinterpret_cast<void *>(this);
}

AuthSessionFsmInterfaceMock::~AuthSessionFsmInterfaceMock()
{
    g_authSessionFsmInterface = nullptr;
}

static AuthSessionFsmInterface *GetAuthSessionFsmMockInterface()
{
    return reinterpret_cast<AuthSessionFsmInterfaceMock *>(g_authSessionFsmInterface);
}

extern "C" {
int32_t AuthManagerSetSessionKey(int64_t authSeq, AuthSessionInfo *info, const SessionKey *sessionKey,
    bool isConnect, bool isOldKey)
{
    return GetAuthSessionFsmMockInterface()->AuthManagerSetSessionKey(authSeq, info, sessionKey, isConnect, isOldKey);
}

int32_t LnnGenerateLocalPtk(char *udid, char *uuid)
{
    return GetAuthSessionFsmMockInterface()->LnnGenerateLocalPtk(udid, uuid);
}

int32_t LnnFsmTransactState(FsmStateMachine *fsm, FsmState *state)
{
    return GetAuthSessionFsmMockInterface()->LnnFsmTransactState(fsm, state);
}

int32_t LnnFsmPostMessage(FsmStateMachine *fsm, uint32_t msgType, void *data)
{
    return GetAuthSessionFsmMockInterface()->LnnFsmPostMessage(fsm, msgType, data);
}

int32_t PostHichainAuthMessage(int64_t authSeq, const AuthSessionInfo *info, const uint8_t *data,
    uint32_t len)
{
    return GetAuthSessionFsmMockInterface()->PostHichainAuthMessage(authSeq, info, data, len);
}

int32_t LnnFsmInit(FsmStateMachine *fsm, SoftBusLooper *looper, char *name, FsmDeinitCallback cb)
{
    return GetAuthSessionFsmMockInterface()->LnnFsmInit(fsm, looper, name, cb);
}

int32_t GetAuthRequestNoLock(uint32_t requestId, AuthRequest *request)
{
    return GetAuthSessionFsmMockInterface()->GetAuthRequestNoLock(requestId, request);
}

int32_t UpdateLocalAuthState(int64_t authSeq, AuthSessionInfo *info)
{
    return GetAuthSessionFsmMockInterface()->UpdateLocalAuthState(authSeq, info);
}

int32_t LnnFsmStart(FsmStateMachine *fsm, FsmState *initialState)
{
    return GetAuthSessionFsmMockInterface()->LnnFsmStart(fsm, initialState);
}

int32_t LnnFsmPostMessageDelay(FsmStateMachine *fsm, uint32_t msgType,
    void *data, uint64_t delayMillis)
{
    return GetAuthSessionFsmMockInterface()->LnnFsmPostMessageDelay(fsm, msgType, data, delayMillis);
}

int32_t PostAuthData(uint64_t connId, bool toServer, const AuthDataHead *head, const uint8_t *data)
{
    return GetAuthSessionFsmMockInterface()->PostAuthData(connId, toServer, head, data);
}

bool GetUdidShortHash(const AuthSessionInfo *info, char *udidBuf, uint32_t bufLen)
{
    return GetAuthSessionFsmMockInterface()->GetUdidShortHash(info, udidBuf, bufLen);
}

int32_t LnnRetrieveDeviceInfo(const char *udidHash, NodeInfo *deviceInfo)
{
    return GetAuthSessionFsmMockInterface()->LnnRetrieveDeviceInfo(udidHash, deviceInfo);
}

bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit)
{
    return GetAuthSessionFsmMockInterface()->IsSupportFeatureByCapaBit(feature, capaBit);
}
}
} // namespace OHOS