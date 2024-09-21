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

#ifndef LNN_OHOS_ACCOUNT_ADAPTER_MOCK_H
#define LNN_OHOS_ACCOUNT_ADAPTER_MOCK_H

#include <gmock/gmock.h>
#include <utility>
#include <atomic>
#include <vector>

#include "account_info.h"

namespace OHOS::AccountSA {
class OhosAccountKits {
public:
    OhosAccountKits() = default;
    virtual ~OhosAccountKits() = default;

    static OhosAccountKits &GetInstance();

    virtual std::pair<bool, OHOS::AccountSA::OhosAccountInfo> QueryOhosAccountInfo();
    virtual bool IsSameAccountGroupDevice(void);
};

class OhosAccountKitsMock : public AccountSA::OhosAccountKits {
public:
    OhosAccountKitsMock();
    ~OhosAccountKitsMock() override;
    MOCK_METHOD0(QueryOhosAccountInfo, std::pair<bool, OHOS::AccountSA::OhosAccountInfo>());
    MOCK_METHOD0(IsSameAccountGroupDevice, bool(void));

    static OhosAccountKitsMock *GetMock()
    {
        return mock.load();
    }

private:
    static inline std::atomic<OhosAccountKitsMock *> mock = nullptr;
};

class OsAccountManager {
public:
    OsAccountManager() = default;
    virtual ~OsAccountManager() = default;

    virtual OHOS::ErrCode QueryActiveOsAccountIds(std::vector<int32_t> &ids);
    virtual OHOS::ErrCode IsOsAccountVerified(const int32_t id, bool &isVerified);
};

class OsAccountManagerMock : public AccountSA::OsAccountManager {
public:
    OsAccountManagerMock();
    ~OsAccountManagerMock() override;
    MOCK_METHOD1(QueryActiveOsAccountIds, OHOS::ErrCode(std::vector<int32_t> &ids));
    MOCK_METHOD2(IsOsAccountVerified, OHOS::ErrCode(const int32_t id, bool &isVerified));

    static OsAccountManagerMock *GetMock()
    {
        return mock.load();
    }

private:
    static inline std::atomic<OsAccountManagerMock *> mock = nullptr;
};
} // namespace OHOS::AccountSA

#endif