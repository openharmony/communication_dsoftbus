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

#ifndef SOFTBUS_PERMISSION_ACL_H
#define SOFTBUS_PERMISSION_ACL_H

#include <atomic>
#include <gmock/gmock.h>
#include <utility>
#include <vector>
#include <map>
#include <string>

#include "account_info.h"
#include "access_control_profile.h"
#include "bus_center_manager.h"


namespace OHOS::AccountSA {
class OsAccountManager {
public:
    OsAccountManager() = default;
    virtual ~OsAccountManager() = default;

    virtual OHOS::ErrCode QueryActiveOsAccountIds(std::vector<int32_t> &ids);
    virtual OHOS::ErrCode IsOsAccountVerified(const int32_t id, bool &isVerified);
};

class OsAccountManagerMock : public OsAccountManager {
public:
    OsAccountManagerMock() = default;
    ~OsAccountManagerMock() = default;
    MOCK_METHOD1(QueryActiveOsAccountIds, OHOS::ErrCode(std::vector<int32_t> &ids));
    MOCK_METHOD2(IsOsAccountVerified, OHOS::ErrCode(const int32_t id, bool &isVerified));
};
} // namespace OHOS::AccountSA

namespace OHOS {
class SoftbusPermissionACLInterface {
public:
    SoftbusPermissionACLInterface() {};
    virtual ~SoftbusPermissionACLInterface() {};
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t TransGetForegroundUserId(void) = 0;
    virtual int32_t SoftBusGetAccessTokenType(uint64_t tokenId) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t TransGetTokenIdBySessionName(const char *sessionName, uint64_t *tokenId) = 0;
    virtual int32_t GetOsAccountLocalIdFromUid_Adapter(const int32_t uid);
    virtual int32_t TransProxyGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid);
    virtual int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len);
    virtual int32_t IsOsAccountForeground_Adapter(const int32_t appUserId, bool &isForegroundUser);
};
class SoftbusPermissionACLInterfaceMock : public SoftbusPermissionACLInterface {
public:
    SoftbusPermissionACLInterfaceMock();
    virtual ~SoftbusPermissionACLInterfaceMock() override;
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t(InfoKey key, char *info, uint32_t len));
    MOCK_METHOD0(TransGetForegroundUserId, int32_t());
    MOCK_METHOD1(SoftBusGetAccessTokenType, int32_t(uint64_t tokenId));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t(const char *networkId, InfoKey key, char *info, uint32_t len));
    MOCK_METHOD2(TransGetTokenIdBySessionName, int32_t(const char *sessionName, uint64_t *tokenId));
    MOCK_METHOD1(GetOsAccountLocalIdFromUid_Adapter, int32_t(const int32_t uid));
    MOCK_METHOD3(TransProxyGetUidAndPidBySessionName, int32_t(const char *sessionName, int32_t *uid, int32_t *pid));
    MOCK_METHOD3(LnnGetNetworkIdByUuid, int32_t(const char *uuid, char *buf, uint32_t len));
    MOCK_METHOD2(IsOsAccountForeground_Adapter, int32_t(const int32_t appUserId, bool &isForegroundUser));


    static SoftbusPermissionACLInterfaceMock *GetMock()
    {
        return mock.load();
    }

private:
    static inline std::atomic<SoftbusPermissionACLInterfaceMock *> mock = nullptr;
};
class IPCSkeleton {
public:
    IPCSkeleton() = default;
    virtual ~IPCSkeleton() = default;

    virtual pid_t GetCallingUid();
    virtual uint64_t GetFirstFullTokenID();
    virtual uint64_t GetCallingFullTokenID();
};
class IPCSkeletonMock : public IPCSkeleton {
public:
    IPCSkeletonMock();
    virtual ~IPCSkeletonMock() override;
    MOCK_METHOD0(GetCallingUid, pid_t());
    MOCK_METHOD0(GetFirstFullTokenID, uint64_t());
    MOCK_METHOD0(GetCallingFullTokenID, uint64_t());

    static IPCSkeletonMock *GetMock()
    {
        return mock.load();
    }

private:
    static inline std::atomic<IPCSkeletonMock *> mock = nullptr;
};
}// namespace OHOS

namespace OHOS::DistributedDeviceProfile {
class DistributedDeviceProfileClient {
public:
    static DistributedDeviceProfileClient& GetInstance() {
        static DistributedDeviceProfileClient instance;
        return instance;
    }

    virtual int32_t GetAccessControlProfile(std::map<std::string, std::string> parms,
        std::vector<AccessControlProfile>& profile);

    virtual ~DistributedDeviceProfileClient() = default;
};

class MockDistributedDeviceProfileClient : public DistributedDeviceProfileClient {
public:
    MOCK_METHOD2(GetAccessControlProfile, 
        int32_t(std::map<std::string, std::string> parms, std::vector<AccessControlProfile>& profile));
};
    
}// namespace OHOS::DistributedDeviceProfile

#endif