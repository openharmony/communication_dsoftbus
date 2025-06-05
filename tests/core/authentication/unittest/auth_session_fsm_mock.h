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

#ifndef AUTH_SESSION_FSM_MOCK_H
#define AUTH_SESSION_FSM_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_connection.h"
#include "auth_interface.h"
#include "auth_manager.h"
#include "auth_session_json.h"
#include "auth_session_message.h"
#include "lnn_device_info_recovery.h"
#include "lnn_p2p_info.h"
#include "lnn_state_machine.h"

namespace OHOS {
class AuthSessionFsmInterface {
public:
    AuthSessionFsmInterface() {};
    virtual ~AuthSessionFsmInterface() {};

    virtual int32_t AuthManagerSetSessionKey(int64_t authSeq, AuthSessionInfo *info, const SessionKey *sessionKey,
        bool isConnect, bool isOldKey) = 0;
    virtual int32_t LnnGenerateLocalPtk(char *udid, char *uuid) = 0;
    virtual int32_t LnnFsmTransactState(FsmStateMachine *fsm, FsmState *state) = 0;
    virtual int32_t LnnFsmPostMessage(FsmStateMachine *fsm, uint32_t msgType, void *data) = 0;
    virtual int32_t PostHichainAuthMessage(int64_t authSeq, const AuthSessionInfo *info, const uint8_t *data,
        uint32_t len) = 0;
    virtual int32_t LnnFsmInit(FsmStateMachine *fsm, SoftBusLooper *looper, char *name, FsmDeinitCallback cb) = 0;
    virtual int32_t GetAuthRequestNoLock(uint32_t requestId, AuthRequest *request) = 0;
    virtual int32_t UpdateLocalAuthState(int64_t authSeq, AuthSessionInfo *info) = 0;
    virtual int32_t LnnFsmStart(FsmStateMachine *fsm, FsmState *initialState) = 0;
    virtual int32_t LnnFsmPostMessageDelay(FsmStateMachine *fsm, uint32_t msgType, void *data,
        uint64_t delayMillis) = 0;
    virtual int32_t PostAuthData(uint64_t connId, bool toServer, const AuthDataHead *head, const uint8_t *data) = 0;
    virtual bool GetUdidShortHash(const AuthSessionInfo *info, char *udidBuf, uint32_t bufLen) = 0;
    virtual int32_t LnnRetrieveDeviceInfo(const char *udidHash, NodeInfo *deviceInfo) = 0;
    virtual bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit) = 0;
};
class AuthSessionFsmInterfaceMock : public AuthSessionFsmInterface {
public:
    AuthSessionFsmInterfaceMock();
    ~AuthSessionFsmInterfaceMock() override;
    MOCK_METHOD5(AuthManagerSetSessionKey, int32_t (int64_t, AuthSessionInfo *, const SessionKey *, bool, bool));
    MOCK_METHOD2(LnnGenerateLocalPtk, int32_t(char *, char *));
    MOCK_METHOD2(LnnFsmTransactState, int32_t (FsmStateMachine *, FsmState *));
    MOCK_METHOD3(LnnFsmPostMessage, int32_t (FsmStateMachine *, uint32_t, void *));
    MOCK_METHOD4(PostHichainAuthMessage, int32_t (int64_t, const AuthSessionInfo *, const uint8_t *, uint32_t));
    MOCK_METHOD4(LnnFsmInit, int32_t (FsmStateMachine *, SoftBusLooper *, char *, FsmDeinitCallback));
    MOCK_METHOD2(GetAuthRequestNoLock, int32_t (uint32_t, AuthRequest *));
    MOCK_METHOD2(UpdateLocalAuthState, int32_t (int64_t, AuthSessionInfo *));
    MOCK_METHOD2(LnnFsmStart, int32_t (FsmStateMachine *, FsmState *));
    MOCK_METHOD4(LnnFsmPostMessageDelay, int32_t (FsmStateMachine *, uint32_t, void *, uint64_t));
    MOCK_METHOD4(PostAuthData, int32_t (uint64_t, bool, const AuthDataHead *ead, const uint8_t *));
    MOCK_METHOD3(GetUdidShortHash, bool (const AuthSessionInfo *, char *, uint32_t));
    MOCK_METHOD2(LnnRetrieveDeviceInfo, int32_t (const char *, NodeInfo *));
    MOCK_METHOD2(IsSupportFeatureByCapaBit, bool (uint32_t, AuthCapability));
};
} // namespace OHOS
#endif // AUTH_SESSION_FSM_MOCK_H