/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <vector>

#include "lnn_log.h"
#include "lnn_ohos_account_adapter.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"
#include "securec.h"
#include "softbus_errcode.h"

static const int32_t ACCOUNT_STRTOLL_BASE = 10;
#define DEFAULT_ACCOUNT_NAME "ohosAnonymousName"

int32_t GetOsAccountId(char *id, uint32_t idLen, uint32_t *len)
{
    if (id == nullptr || len == nullptr || idLen == 0) {
        LNN_LOGE(LNN_STATE, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }

    auto accountInfo = OHOS::AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (!accountInfo.first) {
        LNN_LOGE(LNN_STATE, "QueryOhosAccountInfo failed");
        return SOFTBUS_ERR;
    }

    if (accountInfo.second.name_.empty()) {
        LNN_LOGE(LNN_STATE, "accountInfo uid is empty");
        return SOFTBUS_ERR;
    }

    *len = accountInfo.second.name_.length();
    LNN_LOGI(LNN_STATE, "uid=%{public}s, len=%{public}d", accountInfo.second.name_.c_str(), *len);

    if (memcmp(DEFAULT_ACCOUNT_NAME, accountInfo.second.name_.c_str(), *len) == 0) {
        LNN_LOGE(LNN_STATE, "not login account");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(id, idLen, accountInfo.second.name_.c_str(), *len) != EOK) {
        LNN_LOGE(LNN_STATE, "memcpy_s uid failed, idLen=%{public}d, len=%{public}d", idLen, *len);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int64_t GetCurrentAccount(void)
{
    auto accountInfo = OHOS::AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (!accountInfo.first) {
        LNN_LOGE(LNN_STATE, "QueryOhosAccountInfo failed");
        return 0;
    }

    if (accountInfo.second.name_.empty()) {
        LNN_LOGE(LNN_STATE, "accountInfo name_ is empty");
        return 0;
    }

    LNN_LOGI(LNN_STATE, "name_=%{public}s", accountInfo.second.name_.c_str());
    if (memcmp(DEFAULT_ACCOUNT_NAME, accountInfo.second.name_.c_str(),
        accountInfo.second.name_.length()) == 0) {
        LNN_LOGE(LNN_STATE, "not login account");
        return 0;
    }
    int64_t account = strtoll(accountInfo.second.name_.c_str(), nullptr, ACCOUNT_STRTOLL_BASE);
    if (account == 0) {
        LNN_LOGE(LNN_STATE, "strtoll failed");
    }

    return account;
}

int32_t GetActiveOsAccountIds(void)
{
    std::vector<int32_t> accountId;
    int32_t ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(accountId);
    if (ret != SOFTBUS_OK || accountId.empty()) {
        LNN_LOGE(LNN_STATE, "QueryActiveOsAccountIds failed");
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_STATE, "GetActiveOsAccountIds id=%{public}d", accountId[0]);
    return accountId[0];
}

bool IsActiveOsAccountUnlocked(void)
{
    int32_t osAccountId = GetActiveOsAccountIds();
    if (osAccountId == SOFTBUS_ERR) {
        LNN_LOGE(LNN_STATE, "accountId is invalid");
        return false;
    }
    LNN_LOGI(LNN_STATE, "current active os accountId=%{public}d", osAccountId);
    bool isUnlocked = false;
    OHOS::ErrCode res = OHOS::AccountSA::OsAccountManager::IsOsAccountVerified(osAccountId, isUnlocked);
    if (res != OHOS::ERR_OK) {
        LNN_LOGE(LNN_STATE, "check account verify status failed, res=%{public}d, osAccountId=%{public}d", res,
            osAccountId);
        return false;
    }
    LNN_LOGI(LNN_STATE, "account verified status=%{public}d, accountId=%{public}d", isUnlocked, osAccountId);
    return isUnlocked;
}