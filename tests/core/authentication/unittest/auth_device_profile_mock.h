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

#ifndef AUTH_DEVICE_PROFILE_MOCK_H
#define AUTH_DEVICE_PROFILE_MOCK_H

#include <gmock/gmock.h>

#include "auth_uk_manager.h"
#include "auth_user_common_key.h"
#include "bus_center_info_key.h"
#include "softbus_adapter_file.h"

namespace OHOS {
class AuthDeviceProfileInterface {
public:
    AuthDeviceProfileInterface() {};
    virtual ~AuthDeviceProfileInterface() {};

    virtual int32_t GetActiveOsAccountIds(void) = 0;
    virtual int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info) = 0;
    virtual bool LnnIsDefaultOhosAccount(void) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual bool AuthIsUkExpired(uint64_t time) = 0;
    virtual int32_t AuthInsertUserKey(const AuthACLInfo *aclInfo, const AuthUserKeyInfo *userKeyInfo) = 0;
    virtual uint64_t SoftBusGetSysTimeMs(void) = 0;
};

class AuthDeviceProfileInterfaceMock : public AuthDeviceProfileInterface {
public:
    AuthDeviceProfileInterfaceMock();
    ~AuthDeviceProfileInterfaceMock() override;

    MOCK_METHOD0(GetActiveOsAccountIds, int32_t (void));
    MOCK_METHOD2(LnnGetLocalNum64Info, int32_t (InfoKey, int64_t *));
    MOCK_METHOD0(LnnIsDefaultOhosAccount, bool (void));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey, char *, uint32_t));
    MOCK_METHOD1(AuthIsUkExpired, bool (uint64_t));
    MOCK_METHOD2(AuthInsertUserKey, int32_t (const AuthACLInfo *, const AuthUserKeyInfo *));
    MOCK_METHOD0(SoftBusGetSysTimeMs, uint64_t (void));
};
} // namespace OHOS
#endif
