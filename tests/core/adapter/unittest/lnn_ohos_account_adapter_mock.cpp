/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_ohos_account_adapter_mock.h"
#include "bus_center_event.h"

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

std::pair<bool, OHOS::AccountSA::OhosAccountInfo> OHOS::AccountSA::OhosAccountKits::QueryOsAccountDistributedInfo(
    std::int32_t id)
{
    auto mock = OHOS::AccountSA::OhosAccountKitsMock::GetMock();
    if (mock == nullptr) {
        std::pair<bool, OHOS::AccountSA::OhosAccountInfo> account_info = {};
        return account_info;
    }
    return mock->QueryOsAccountDistributedInfo(id);
}

int32_t OHOS::AccountSA::OhosAccountKits::GetOsAccountDistributedInfo(int32_t localId,
    OHOS::AccountSA::OhosAccountInfo &accountInfo)
{
    auto mock = OHOS::AccountSA::OhosAccountKitsMock::GetMock();
    if (mock == nullptr) {
        return OHOS::ERR_INVALID_OPERATION;
    }
    return mock->GetOsAccountDistributedInfo(localId, accountInfo);
}

bool OHOS::AccountSA::OhosAccountKits::IsSameAccountGroupDevice()
{
    auto mock = OHOS::AccountSA::OhosAccountKitsMock::GetMock();
    if (mock == nullptr) {
        return false;
    }
    return mock->IsSameAccountGroupDevice();
}

int32_t OHOS::AccountSA::OhosAccountKits::LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    auto mock = OHOS::AccountSA::OhosAccountKitsMock::GetMock();
    if (mock == nullptr) {
        return OHOS::ERR_INVALID_OPERATION;
    }
    return mock->LnnGetLocalNumU64Info(key, info);
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

extern "C" {
void LnnNotifyConstraintStateChangeEvent(bool isConstraint)
{
    (void)isConstraint;
}
} // extern "C"

OHOS::ErrCode OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(std::vector<int32_t> &ids)
{
    auto mock = OHOS::AccountSA::OsAccountManagerMock::GetMock();
    if (mock == nullptr) {
        return OHOS::ERR_INVALID_OPERATION;
    }
    return mock->QueryActiveOsAccountIds(ids);
}

OHOS::ErrCode OHOS::AccountSA::OsAccountManager::IsOsAccountVerified(const int32_t id, bool &isVerified)
{
    auto mock = OHOS::AccountSA::OsAccountManagerMock::GetMock();
    if (mock == nullptr) {
        return OHOS::ERR_INVALID_OPERATION;
    }
    return mock->IsOsAccountVerified(id, isVerified);
}

OHOS::ErrCode OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(int32_t &id)
{
    auto mock = OHOS::AccountSA::OsAccountManagerMock::GetMock();
    if (mock == nullptr) {
        return OHOS::ERR_INVALID_OPERATION;
    }
    return mock->GetOsAccountLocalIdFromProcess(id);
}

OHOS::ErrCode OHOS::AccountSA::OsAccountManager::CheckOsAccountConstraintEnabled(
    int32_t id, const std::string &constraint, bool &isEnabled)
{
    auto mock = OHOS::AccountSA::OsAccountManagerMock::GetMock();
    if (mock == nullptr) {
        return OHOS::ERR_INVALID_OPERATION;
    }
    return mock->CheckOsAccountConstraintEnabled(id, constraint, isEnabled);
}

OHOS::ErrCode OHOS::AccountSA::OsAccountManager::SubscribeOsAccountConstraints(
    const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber)
{
    auto mock = OHOS::AccountSA::OsAccountManagerMock::GetMock();
    if (mock == nullptr) {
        return OHOS::ERR_INVALID_OPERATION;
    }
    return mock->SubscribeOsAccountConstraints(subscriber);
}

OHOS::ErrCode OHOS::AccountSA::OsAccountManager::UnsubscribeOsAccountConstraints(
    const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber)
{
    auto mock = OHOS::AccountSA::OsAccountManagerMock::GetMock();
    if (mock == nullptr) {
        return OHOS::ERR_INVALID_OPERATION;
    }
    return mock->UnsubscribeOsAccountConstraints(subscriber);
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