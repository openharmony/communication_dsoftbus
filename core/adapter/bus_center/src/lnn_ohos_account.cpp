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

#include "bus_center_manager.h"
#include "lnn_heartbeat_ctrl.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"
#include "softbus_adapter_crypto.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

static const std::string DEFAULT_USER_ID = "0";

int32_t LnnGetOhosAccountInfo(uint8_t *accountHash, uint32_t len)
{
    if (accountHash == nullptr || len != SHA_256_HASH_LEN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetOhosAccount get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    (void)memset_s(accountHash, len, 0, len);
    if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(DEFAULT_USER_ID.c_str()), DEFAULT_USER_ID.length(),
        reinterpret_cast<unsigned char *>(accountHash)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetOhosAccount generate default str hash fail");
        return SOFTBUS_ERR;
    }

    std::vector<int32_t> ids;
    OHOS::ErrCode ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != OHOS::ERR_OK || ids.size() == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetOhosAccount get ids fail");
        return SOFTBUS_ERR;
    }

    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> accountInfo
        = OHOS::AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfoByUserId(ids[0]);
    if (!accountInfo.first) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetOhosAccount query fail");
        return SOFTBUS_ERR;
    }

    if (accountInfo.second.uid_.empty() ||
        accountInfo.second.uid_ == DEFAULT_USER_ID ||
        accountInfo.second.uid_ == OHOS::AccountSA::DEFAULT_OHOS_ACCOUNT_UID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "GetOhosAccount get default account hash");
        return SOFTBUS_OK;
    }

    return ConvertHexStringToBytes(reinterpret_cast<unsigned char *>(accountHash), len,
        accountInfo.second.uid_.c_str(), accountInfo.second.uid_.length());
}

int32_t LnnInitOhosAccount(void)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};

    if (LnnGetOhosAccountInfo(accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(DEFAULT_USER_ID.c_str()), DEFAULT_USER_ID.length(),
            reinterpret_cast<unsigned char *>(accountHash)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "InitOhosAccount generate default str hash fail");
            return SOFTBUS_ERR;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "init accountHash [%02X %02X]", accountHash[0], accountHash[1]);
    return LnnSetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN);
}

void LnnOnOhosAccountChanged(void)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    uint8_t localAccountHash[SHA_256_HASH_LEN] = {0};

    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnAccountChanged get local account hash fail");
        return;
    }
    if (LnnGetOhosAccountInfo(accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "OnAccountChanged get account account hash fail");
        if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(DEFAULT_USER_ID.c_str()), DEFAULT_USER_ID.length(),
            reinterpret_cast<unsigned char *>(accountHash)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnAccountChanged generate default str hash fail");
            return;
        }
    }
    if (memcmp(accountHash, localAccountHash, SHA_256_HASH_LEN) == EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "OnAccountChanged account not change");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "accountHash from [%02X %02X] changed to [%02X %02X]",
        localAccountHash[0], localAccountHash[1], accountHash[0], accountHash[1]);
    LnnSetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN);
    DiscDeviceInfoChanged(TYPE_ACCOUNT);
    LnnUpdateHeartbeatInfo(UPDATE_HB_ACCOUNT_INFO);
}

bool LnnIsDefaultOhosAccount(void)
{
    uint8_t localAccountHash[SHA_256_HASH_LEN] = {0};
    uint8_t defaultAccountHash[SHA_256_HASH_LEN] = {0};

    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "IsDefaultOhosAccount get local accountHash fail");
        return false;
    }
    if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(DEFAULT_USER_ID.c_str()), DEFAULT_USER_ID.length(),
        reinterpret_cast<unsigned char *>(defaultAccountHash)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "IsDefaultOhosAccount generate default str hash fail");
        return false;
    }
    return memcmp(localAccountHash, defaultAccountHash, SHA_256_HASH_LEN) == 0;
}
