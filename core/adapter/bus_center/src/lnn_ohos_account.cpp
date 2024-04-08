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
#include "lnn_ohos_account.h"

#include <securec.h>

#include "bus_center_manager.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_log.h"
#include "ohos_account_kits.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"

static const std::string DEFAULT_USER_ID = "0";

int32_t LnnGetOhosAccountInfo(uint8_t *accountHash, uint32_t len)
{
    if (accountHash == nullptr || len != SHA_256_HASH_LEN) {
        LNN_LOGE(LNN_STATE, "GetOhosAccount get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    (void)memset_s(accountHash, len, 0, len);
    if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(DEFAULT_USER_ID.c_str()),
        DEFAULT_USER_ID.length(), reinterpret_cast<unsigned char *>(accountHash)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "GetOhosAccount generate default str hash fail");
        return SOFTBUS_ERR;
    }
    char *accountInfo = (char *)SoftBusMalloc(len * HEXIFY_UNIT_LEN);
    if (accountInfo == nullptr) {
        LNN_LOGE(LNN_STATE, "accountInfo malloc fail");
        return SOFTBUS_ERR;
    }
    (void)memset_s(accountInfo, len * HEXIFY_UNIT_LEN, '0', len * HEXIFY_UNIT_LEN);
    uint32_t size = 0;
    if (GetOsAccountId(accountInfo, len * HEXIFY_UNIT_LEN, &size) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get osAccountId fail");
        SoftBusFree(accountInfo);
        return SOFTBUS_ERR;
    }
    if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(accountInfo), size,
        reinterpret_cast<unsigned char *>(accountHash)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "GetOhosAccount generate str hash fail");
        SoftBusFree(accountInfo);
        return SOFTBUS_ERR;
    }
    SoftBusFree(accountInfo);
    return SOFTBUS_OK;
}

int32_t LnnInitOhosAccount(void)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};

    if (LnnGetOhosAccountInfo(accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(DEFAULT_USER_ID.c_str()),
            DEFAULT_USER_ID.length(), reinterpret_cast<unsigned char *>(accountHash)) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "InitOhosAccount generate default str hash fail");
            return SOFTBUS_ERR;
        }
    }
    int64_t accountId = GetCurrentAccount();
    (void)LnnSetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, accountId);
    LNN_LOGD(LNN_STATE, "init accountHash. accountHash[0]=%{public}02X, accountHash[1]=%{public}02X",
        accountHash[0], accountHash[1]);
    return LnnSetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN);
}

void LnnUpdateOhosAccount(void)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    uint8_t localAccountHash[SHA_256_HASH_LEN] = {0};

    (void)LnnSetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, GetCurrentAccount());
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "OnAccountChanged get local account hash fail");
        return;
    }
    if (LnnGetOhosAccountInfo(accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGW(LNN_STATE, "OnAccountChanged get account account hash fail");
        if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(DEFAULT_USER_ID.c_str()),
            DEFAULT_USER_ID.length(), reinterpret_cast<unsigned char *>(accountHash)) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "OnAccountChanged generate default str hash fail");
            return;
        }
    }
    if (memcmp(accountHash, localAccountHash, SHA_256_HASH_LEN) == EOK) {
        LNN_LOGD(LNN_STATE, "accountHash not changed, accountHash=[%{public}02X, %{public}02X]",
            accountHash[0], accountHash[1]);
        return;
    }
    LNN_LOGI(LNN_STATE,
        "accountHash update. localAccountHash=[%{public}02X, %{public}02X], accountHash=[%{public}02X, %{public}02X]",
        localAccountHash[0], localAccountHash[1], accountHash[0], accountHash[1]);
    LnnSetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN);
    DiscDeviceInfoChanged(TYPE_ACCOUNT);
    LnnUpdateHeartbeatInfo(UPDATE_HB_ACCOUNT_INFO);
}

void LnnOnOhosAccountLogout(void)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};

    (void)LnnSetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, 0);
    if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(DEFAULT_USER_ID.c_str()),
        DEFAULT_USER_ID.length(), reinterpret_cast<unsigned char *>(accountHash)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "OnAccountChanged generate default str hash fail");
        return;
    }
    LNN_LOGI(LNN_STATE,
        "accountHash changed. accountHash=[%{public}02X, %{public}02X]", accountHash[0], accountHash[1]);
    LnnSetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN);
    DiscDeviceInfoChanged(TYPE_ACCOUNT);
    LnnUpdateHeartbeatInfo(UPDATE_HB_ACCOUNT_INFO);
}

bool LnnIsDefaultOhosAccount(void)
{
    uint8_t localAccountHash[SHA_256_HASH_LEN] = {0};
    uint8_t defaultAccountHash[SHA_256_HASH_LEN] = {0};

    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "IsDefaultOhosAccount get local accountHash fail");
        return false;
    }
    if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(DEFAULT_USER_ID.c_str()),
        DEFAULT_USER_ID.length(), reinterpret_cast<unsigned char *>(defaultAccountHash)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "IsDefaultOhosAccount generate default str hash fail");
        return false;
    }
    return memcmp(localAccountHash, defaultAccountHash, SHA_256_HASH_LEN) == 0;
}
