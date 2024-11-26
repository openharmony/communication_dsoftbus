/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef AUTH_MOCK_H
#define AUTH_MOCK_H

#include <gmock/gmock.h>

#include "auth_interface.h"

namespace OHOS {
class AuthInterface {
public:
    AuthInterface() {};
    virtual ~AuthInterface() {};

    virtual void AuthHandleLeaveLNN(AuthHandle authHandle) = 0;
    virtual uint32_t AuthGenRequestId(void) = 0;
    virtual int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId,
        const AuthVerifyCallback *callback, AuthVerifyModule module, bool isFastAuth) = 0;
    virtual int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version) = 0;
    virtual int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size) = 0;
    virtual int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener) = 0;
    virtual void UnregAuthTransListener(int32_t module) = 0;
    virtual int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo) = 0;
    virtual int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta) = 0;
    virtual int32_t AuthFlushDevice(const char *uuid) = 0;
    virtual int32_t AuthSendKeepaliveOption(const char *uuid, ModeCycle cycle) = 0;
};
class AuthInterfaceMock : public AuthInterface {
public:
    AuthInterfaceMock();
    ~AuthInterfaceMock() override;
    MOCK_METHOD(void, AuthHandleLeaveLNN, (AuthHandle), (override));
    MOCK_METHOD(uint32_t, AuthGenRequestId, (), (override));
    MOCK_METHOD(int32_t, AuthStartVerify,
        (const AuthConnInfo *, uint32_t, const AuthVerifyCallback *, AuthVerifyModule, bool), (override));
    MOCK_METHOD(int32_t, AuthGetVersion, (int64_t, SoftBusVersion *), (override));
    MOCK_METHOD(int32_t, AuthGetDeviceUuid, (int64_t, char *, uint16_t), (override));

    MOCK_METHOD2(RegAuthTransListener, int32_t(int32_t, const AuthTransListener *));
    MOCK_METHOD1(UnregAuthTransListener, void(int32_t));
    MOCK_METHOD2(AuthPostTransData, int32_t(AuthHandle, const AuthTransData *));
    MOCK_METHOD3(AuthGetIdByConnInfo, int64_t(const AuthConnInfo *, bool, bool));
    MOCK_METHOD1(AuthFlushDevice, int32_t(const char *));
    MOCK_METHOD2(AuthSendKeepaliveOption, int32_t(const char *, ModeCycle));
};
} // namespace OHOS
#endif // AUTH_MOCK_H