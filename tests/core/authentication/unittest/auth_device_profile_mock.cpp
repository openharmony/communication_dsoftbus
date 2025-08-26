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

#include "auth_device_profile_mock.h"

namespace OHOS {
void *g_authDeviceProfileIterface;

AuthDeviceProfileInterfaceMock::AuthDeviceProfileInterfaceMock()
{
    g_authDeviceProfileIterface = reinterpret_cast<void *>(this);
}

AuthDeviceProfileInterfaceMock::~AuthDeviceProfileInterfaceMock()
{
    g_authDeviceProfileIterface = nullptr;
}

static AuthDeviceProfileInterfaceMock *GetInterface()
{
    return reinterpret_cast<AuthDeviceProfileInterfaceMock *>(g_authDeviceProfileIterface);
}

extern "C" {
int32_t GetActiveOsAccountIds(void)
{
    return GetInterface()->GetActiveOsAccountIds();
}

int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    return GetInterface()->LnnGetLocalNum64Info(key, info);
}

bool LnnIsDefaultOhosAccount(void)
{
    return GetInterface()->LnnIsDefaultOhosAccount();
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetInterface()->LnnGetLocalStrInfo(key, info, len);
}

bool AuthIsUkExpired(uint64_t time)
{
    return GetInterface()->AuthIsUkExpired(time);
}

int32_t AuthInsertUserKey(const AuthACLInfo *aclInfo, const AuthUserKeyInfo *userKeyInfo, bool isUserBindLevel)
{
    return GetInterface()->AuthInsertUserKey(aclInfo, userKeyInfo, isUserBindLevel);
}

uint64_t SoftBusGetSysTimeMs(void)
{
    return GetInterface()->SoftBusGetSysTimeMs();
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen)
{
    return GetInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return GetInterface()->LnnGetLocalByteInfo(key, info, len);
}

int32_t IdServiceGetCredInfoByUdid(const char *udid, SoftBusCredInfo *credInfo)
{
    return GetInterface()->IdServiceGetCredInfoByUdid(udid, credInfo);
}

int32_t RegisterToDp(DeviceProfileChangeListener *deviceProfilePara)
{
    return GetInterface()->RegisterToDp(deviceProfilePara);
}

int32_t GetUserKeyByUkId(int32_t sessionKeyId, uint8_t *uk, uint32_t ukLen)
{
    return GetInterface()->GetUserKeyByUkId(sessionKeyId, uk, ukLen);
}

int32_t CheckAclInfoIsAccesser(const AuthACLInfo *acl, bool *isAccesser)
{
    return GetInterface()->CheckAclInfoIsAccesser(acl, isAccesser);
}
}
} // namespace OHOS