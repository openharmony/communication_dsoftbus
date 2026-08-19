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
#include "bus_center_manager.h"
#include "lnn_log.h"
#include "lnn_ohos_account.h"
#include "softbus_adapter_crypto.h"
#include "softbus_error_code.h"

static const char DEFAULT_USER_ID[] = "0";
static const char DEFAULT_ACCOUNT_UID[] = "ohosAnonymousUid";

int32_t LnnGetOhosAccountInfo(uint8_t *accountHash, uint32_t len)
{
    (void)accountHash;
    (void)len;
    return SOFTBUS_OK;
}

int32_t LnnGetOhosAccountInfoByUserId(int32_t userId, uint8_t *accountHash, uint32_t len)
{
    (void)userId;
    (void)accountHash;
    (void)len;
    return SOFTBUS_OK;
}

int32_t LnnGetAccountIdByUserId(int32_t userId, int64_t *accountId, uint8_t *accountHash, uint32_t len)
{
    (void)userId;
    (void)accountId;
    (void)accountHash;
    (void)len;
    return SOFTBUS_OK;
}

int32_t LnnInitOhosAccount(void)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};

    if (SoftBusGenerateStrHash((const unsigned char *)DEFAULT_USER_ID,
        sizeof(DEFAULT_USER_ID) - 1, (unsigned char *)accountHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "InitOhosAccount generate default str hash fail");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }

    LnnSetLocalStrInfo(STRING_KEY_ACCOUNT_UID, DEFAULT_ACCOUNT_UID);
    LNN_LOGI(LNN_STATE, "init accountHash. accountHash[0]=%{public}02X, accountHash[1]=%{public}02X",
        accountHash[0], accountHash[1]);
    return LnnSetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN);
}

void LnnUpdateOhosAccount(UpdateAccountReason reason)
{
    (void)reason;
}

void LnnOnOhosAccountLogout(void)
{
}

bool LnnIsDefaultOhosAccount(void)
{
    return true;
}

int32_t LnnJudgeDeviceTypeAndGetOsAccountInfo(uint8_t *accountHash, uint32_t len)
{
    (void)accountHash;
    (void)len;
    return SOFTBUS_OK;
}