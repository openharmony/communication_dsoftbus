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

#ifndef AUTH_AUTH_SESSION_FSM_MOCK_H
#define AUTH_AUTH_SESSION_FSM_MOCK_H

#include <gmock/gmock.h>

#include "auth_request.h"
#include "auth_session_fsm_struct.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_node_info_struct.h"

namespace OHOS {
class AuthSessionFsmInterface {
public:
    AuthSessionFsmInterface() {};
    virtual ~AuthSessionFsmInterface() {};

    virtual int32_t SoftBusGetBrState(void) = 0;
    virtual bool GetUdidShortHash(const AuthSessionInfo *info, char *udidBuf, uint32_t bufLen) = 0;
    virtual int32_t LnnRetrieveDeviceInfoPacked(const char *udid, NodeInfo *deviceInfo) = 0;
    virtual bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit) = 0;
    virtual int32_t GetAuthRequest(uint32_t requestId, AuthRequest *request) = 0;
    virtual int32_t LnnRetrieveDeviceInfoByUdidPacked(const char *udid, NodeInfo *deviceInfo) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual int32_t PostDeviceInfoMessage(int64_t authSeq, const AuthSessionInfo *info) = 0;
    virtual int32_t ProcessDeviceIdMessage(AuthSessionInfo *info, const uint8_t *data, uint32_t len,
        int64_t authSeq) = 0;
    virtual int32_t PostDeviceIdMessage(int64_t authSeq, const AuthSessionInfo *info) = 0;
    virtual bool LnnIsNeedInterceptBroadcast(bool disableGlass) = 0;
};

class AuthSessionFsmInterfaceMock : public AuthSessionFsmInterface {
public:
    AuthSessionFsmInterfaceMock();
    ~AuthSessionFsmInterfaceMock() override;

    MOCK_METHOD0(SoftBusGetBrState, int32_t (void));
    MOCK_METHOD3(GetUdidShortHash, bool (const AuthSessionInfo *, char *, uint32_t));
    MOCK_METHOD2(LnnRetrieveDeviceInfoPacked, int32_t (const char *, NodeInfo *));
    MOCK_METHOD2(IsSupportFeatureByCapaBit, bool (uint32_t, AuthCapability));
    MOCK_METHOD2(GetAuthRequest, int32_t (uint32_t, AuthRequest *));
    MOCK_METHOD2(LnnRetrieveDeviceInfoByUdidPacked, int32_t (const char *, NodeInfo *));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char *, IdCategory, NodeInfo *));
    MOCK_METHOD2(PostDeviceInfoMessage, int32_t (int64_t, const AuthSessionInfo *));
    MOCK_METHOD4(ProcessDeviceIdMessage, int32_t (AuthSessionInfo *, const uint8_t *, uint32_t, int64_t));
    MOCK_METHOD2(PostDeviceIdMessage, int32_t (int64_t, const AuthSessionInfo *));
    MOCK_METHOD1(LnnIsNeedInterceptBroadcast, bool (bool));
};
}
#endif // AUTH_AUTH_SESSION_FSM_MOCK_H
