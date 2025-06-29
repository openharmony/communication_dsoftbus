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

#include "auth_session_fsm_struct.h"
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
};

class AuthSessionFsmInterfaceMock : public AuthSessionFsmInterface {
public:
    AuthSessionFsmInterfaceMock();
    ~AuthSessionFsmInterfaceMock() override;

    MOCK_METHOD0(SoftBusGetBrState, int32_t (void));
    MOCK_METHOD3(GetUdidShortHash, bool (const AuthSessionInfo *, char *, uint32_t));
    MOCK_METHOD2(LnnRetrieveDeviceInfoPacked, int32_t (const char *, NodeInfo *));
    MOCK_METHOD2(IsSupportFeatureByCapaBit, bool (uint32_t, AuthCapability));
};
}
#endif // AUTH_AUTH_SESSION_FSM_MOCK_H
