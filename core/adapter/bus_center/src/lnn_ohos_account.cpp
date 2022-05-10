/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "lnn_ohos_account.h"

#include <securec.h>
#include "ohos_account_kits.h"
#include "os_account_manager.h"
#include "softbus_adapter_crypto.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

static const char *DEFAULT_USER_ID = "0";

int32_t LnnGetOhosAccountInfo(uint8_t *accountHash, uint32_t len)
{
    if (accountHash == nullptr || len != SHA_256_HASH_LEN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetOhosAccountInfo invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    (void)memset_s(accountHash, len, 0, len);
    std::vector<int32_t> ids;
    OHOS::ErrCode ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != OHOS::ERR_OK || ids.size() == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetOhosAccountInfo get ids fail");
        return SOFTBUS_ERR;
    }

    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> accountInfo
        = OHOS::AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfoByUserId(ids[0]);
    if (!accountInfo.first) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetOhosAccountInfo query fail");
        return SOFTBUS_ERR;
    }

    if (accountInfo.second.uid_.empty() || accountInfo.second.uid_ == DEFAULT_USER_ID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetOhosAccountInfo get default user id");
        return SOFTBUS_OK;
    }

    return ConvertHexStringToBytes((unsigned char *)accountHash, len,
        accountInfo.second.uid_.c_str(), accountInfo.second.uid_.length());
}