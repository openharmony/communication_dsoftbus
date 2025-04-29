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

int32_t AuthInsertUserKey(const AuthACLInfo *aclInfo, const AuthUserKeyInfo *userKeyInfo)
{
    return GetInterface()->AuthInsertUserKey(aclInfo, userKeyInfo);
}

uint64_t SoftBusGetSysTimeMs(void)
{
    return GetInterface()->SoftBusGetSysTimeMs();
}
}