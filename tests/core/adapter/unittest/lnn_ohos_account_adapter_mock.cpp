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

#include "lnn_ohos_account_adapter_mock.h"

OHOS::AccountSA::OhosAccountKits &OHOS::AccountSA::OhosAccountKits::GetInstance()
{
    static OhosAccountKits ohosAccountKits;
    return ohosAccountKits;
}

std::pair<bool, OHOS::AccountSA::OhosAccountInfo> OHOS::AccountSA::OhosAccountKits::QueryOhosAccountInfo()
{
    auto mock = OHOS::AccountSA::OhosAccountKitsMock::GetMock();
    if (mock == nullptr) {
        std::pair<bool, OHOS::AccountSA::OhosAccountInfo> account_info = {};
        return account_info;
    }
    return mock->QueryOhosAccountInfo();
}

bool OHOS::AccountSA::OhosAccountKits::IsSameAccountGroupDevice()
{
    auto mock = OHOS::AccountSA::OhosAccountKitsMock::GetMock();
    if (mock == nullptr) {
        return false;
    }
    return mock->IsSameAccountGroupDevice();
}

namespace OHOS::AccountSA {
OhosAccountKitsMock::OhosAccountKitsMock()
{
    mock.store(this);
}

OhosAccountKitsMock::~OhosAccountKitsMock()
{
    mock.store(nullptr);
}

extern "C" {
bool IsSameAccountGroupDevice(void)
{
    auto mock = OHOS::AccountSA::OhosAccountKitsMock::GetMock();
    if (mock == nullptr) {
        return false;
    }
    return mock->IsSameAccountGroupDevice();
}
}

} // namespace OHOS::AccountSA

OHOS::ErrCode OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(std::vector<int32_t> &ids)
{
    auto mock = OHOS::AccountSA::OsAccountManagerMock::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->QueryActiveOsAccountIds(ids);
}

OHOS::ErrCode OHOS::AccountSA::OsAccountManager::IsOsAccountVerified(const int32_t id, bool &isVerified)
{
    auto mock = OHOS::AccountSA::OsAccountManagerMock::GetMock();
    if (mock == nullptr) {
        return -1;
    }
    return mock->IsOsAccountVerified(id, isVerified);
}

namespace OHOS::AccountSA {
OsAccountManagerMock::OsAccountManagerMock()
{
    mock.store(this);
}

OsAccountManagerMock::~OsAccountManagerMock()
{
    mock.store(nullptr);
}
} // namespace OHOS::AccountSA