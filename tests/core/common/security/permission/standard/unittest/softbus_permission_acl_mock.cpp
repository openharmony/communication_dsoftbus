/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "softbus_permission_acl_mock.h"

namespace OHOS::AccountSA {

    OHOS::ErrCode OsAccountManager::QueryActiveOsAccountIds(std::vector<int32_t> &ids)
    {
        return ERR_OK;
    }

    OHOS::ErrCode OsAccountManager::IsOsAccountVerified(const int32_t id, bool &isVerified)
    {
        
        return ERR_OK;
    }
}

namespace OHOS {
SoftbusPermissionACLInterfaceMock::SoftbusPermissionACLInterfaceMock()
{
    mock.store(this);
}

SoftbusPermissionACLInterfaceMock::~SoftbusPermissionACLInterfaceMock()
{
    mock.store(nullptr);
}

IPCSkeletonMock::IPCSkeletonMock()
{
    mock.store(this);
}

IPCSkeletonMock::~IPCSkeletonMock()
{
    mock.store(nullptr);
}

pid_t IPCSkeleton::GetCallingUid()
{
    auto mock = IPCSkeletonMock::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->GetCallingUid();
}

uint64_t IPCSkeleton::GetFirstFullTokenID()
{
    auto mock = IPCSkeletonMock::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->GetFirstFullTokenID();
}

uint64_t IPCSkeleton::GetCallingFullTokenID()
{
    auto mock = IPCSkeletonMock::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->GetCallingFullTokenID();
}

extern "C"{
int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return SoftbusPermissionACLInterfaceMock::GetMock()->LnnGetLocalStrInfo(key, info, len);
}

int32_t TransGetForegroundUserId()
{
    return SoftbusPermissionACLInterfaceMock::GetMock()->TransGetForegroundUserId();
}

int32_t SoftBusGetAccessTokenType(uint64_t tokenId)
{
    return SoftbusPermissionACLInterfaceMock::GetMock()->SoftBusGetAccessTokenType(tokenId);
}

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    return SoftbusPermissionACLInterfaceMock::GetMock()->LnnGetRemoteStrInfo(networkId, key, info, len);
}

int32_t TransGetTokenIdBySessionName(const char *sessionName, uint64_t *tokenId)
{
    return SoftbusPermissionACLInterfaceMock::GetMock()->TransGetTokenIdBySessionName(sessionName, tokenId);
}

int32_t GetOsAccountLocalIdFromUid_Adapter(const int32_t uid)
{
    return SoftbusPermissionACLInterfaceMock::GetMock()->GetOsAccountLocalIdFromUid_Adapter(uid);
}

int32_t TransProxyGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid)
{
    return SoftbusPermissionACLInterfaceMock::GetMock()->TransProxyGetUidAndPidBySessionName(sessionName, uid, pid);
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    return SoftbusPermissionACLInterfaceMock::GetMock()->LnnGetNetworkIdByUuid(uuid, buf, len);
}

int32_t IsOsAccountForeground_Adapter(const int32_t appUserId, bool &isForegroundUser)
{
    return SoftbusPermissionACLInterfaceMock::GetMock()->IsOsAccountForeground_Adapter(appUserId, isForegroundUser);
}
}
} // namespace OHOS

namespace OHOS::DistributedDeviceProfile {
int32_t DistributedDeviceProfileClient::GetAccessControlProfile(std::map<std::string, std::string> parms,
    std::vector<AccessControlProfile>& profile)
{
    if (profile.empty()) {
        int32_t bindLevelTest = 1;
        int32_t bindTypeTest = 4;
        for (int i = 0; i < 3; ++i){
            AccessControlProfile item;
            item.SetBindLevel(bindLevelTest++);
            item.SetBindType(bindTypeTest++);
            profile.push_back(item);
        }
    }
    return 0;
}
}