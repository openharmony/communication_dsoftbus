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

#include "auth_device_profile_listener.h"
#include "auth_identity_service_adapter.h"
#include "auth_log.h"
#include "auth_uk_manager.h"
#include "auth_user_common_key.h"
#include "bus_center_info_key.h"
#include "device_profile_listener.h"
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
    virtual int32_t AuthInsertUserKey(
        const AuthACLInfo *aclInfo, const AuthUserKeyInfo *userKeyInfo, bool isUserBindLevel) = 0;
    virtual uint64_t SoftBusGetSysTimeMs(void) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t ConvertBytesToHexString(
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual int32_t IdServiceGetCredInfoByUdid(const char *udid, SoftBusCredInfo *credInfo);
    virtual int32_t RegisterToDp(DeviceProfileChangeListener *deviceProfilePara) = 0;
    virtual int32_t GetUserKeyByUkId(int32_t sessionKeyId, uint8_t *uk, uint32_t ukLen) = 0;
    virtual int32_t CheckAclInfoIsAccesser(const AuthACLInfo *acl, bool *isAccesser) = 0;
    virtual int32_t LnnJudgeDeviceTypeAndGetOsAccountInfo(uint8_t *accountHash, uint32_t len) = 0;
    virtual int32_t JudgeDeviceTypeAndGetOsAccountIds(void) = 0;
};

class AuthDeviceProfileInterfaceMock : public AuthDeviceProfileInterface {
public:
    AuthDeviceProfileInterfaceMock();
    ~AuthDeviceProfileInterfaceMock() override;

    MOCK_METHOD0(GetActiveOsAccountIds, int32_t(void));
    MOCK_METHOD2(LnnGetLocalNum64Info, int32_t(InfoKey, int64_t *));
    MOCK_METHOD0(LnnIsDefaultOhosAccount, bool(void));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t(InfoKey, char *, uint32_t));
    MOCK_METHOD1(AuthIsUkExpired, bool(uint64_t));
    MOCK_METHOD3(AuthInsertUserKey, int32_t(const AuthACLInfo *, const AuthUserKeyInfo *, bool));
    MOCK_METHOD0(SoftBusGetSysTimeMs, uint64_t(void));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t(const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t(char *, uint32_t, const unsigned char *, uint32_t inLen));
    MOCK_METHOD3(LnnGetLocalByteInfo, int32_t(InfoKey, uint8_t *, uint32_t));
    MOCK_METHOD2(IdServiceGetCredInfoByUdid, int32_t(const char *, SoftBusCredInfo *));
    MOCK_METHOD1(RegisterToDp, int32_t(DeviceProfileChangeListener *));
    MOCK_METHOD3(GetUserKeyByUkId, int32_t(int32_t, uint8_t *, uint32_t));
    MOCK_METHOD2(CheckAclInfoIsAccesser, int32_t(const AuthACLInfo *, bool *));
    MOCK_METHOD2(LnnJudgeDeviceTypeAndGetOsAccountInfo, int32_t(uint8_t *, uint32_t));
    MOCK_METHOD0(JudgeDeviceTypeAndGetOsAccountIds, int32_t(void));
};
} // namespace OHOS
#endif