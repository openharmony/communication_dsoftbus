/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <string>

#include "auth_hichain_adapter.h"
#include "auth_manager.h"
#include "bus_center_manager.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_decision_db.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_log.h"
#include "lnn_connection_fsm.h"
#include "lnn_init_monitor.h"
#include "softbus_adapter_mem.h"

static const std::string DEFAULT_USER_ID = "0";
static const std::string DEFAULT_ACCOUNT_UID = "ohosAnonymousUid";
static bool g_accountIdInited = false;

int32_t LnnJudgeDeviceTypeAndGetOsAccountInfo(uint8_t *accountHash, uint32_t len)
{
    int32_t userId = 0;
    int32_t localDevTypeId = 0;
    if (accountHash == nullptr) {
        LNN_LOGE(LNN_STATE, "GetOhosAccount get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "GeLocalDevType get invalid param");
        return LnnGetOhosAccountInfo(accountHash, SHA_256_HASH_LEN);
    }
    if (localDevTypeId == TYPE_CAR_ID) {
        LnnGetLocalNumInfo(NUM_KEY_USERID, &userId);
        if (LnnGetOhosAccountInfoByUserId(userId, accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "GetOhosAccountInfo get invalid param");
            return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED;
        }
    } else if (LnnGetOhosAccountInfo(accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "GetOhosAccountInfo get invalid param");
        return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED;
    }
    return SOFTBUS_OK;
}

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
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    char *accountInfo = (char *)SoftBusMalloc(len * HEXIFY_UNIT_LEN);
    if (accountInfo == nullptr) {
        LNN_LOGE(LNN_STATE, "accountInfo malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    (void)memset_s(accountInfo, len * HEXIFY_UNIT_LEN, '0', len * HEXIFY_UNIT_LEN);
    uint32_t size = 0;
    int32_t ret = GetOsAccountId(accountInfo, len * HEXIFY_UNIT_LEN, &size);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get osAccountId fail");
        SoftBusFree(accountInfo);
        return ret;
    }
    if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(accountInfo), size,
        reinterpret_cast<unsigned char *>(accountHash)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "GetOhosAccount generate str hash fail");
        SoftBusFree(accountInfo);
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    SoftBusFree(accountInfo);
    return SOFTBUS_OK;
}

int32_t LnnGetOhosAccountInfoByUserId(int32_t userId, uint8_t *accountHash, uint32_t len)
{
    if (accountHash == nullptr || len != SHA_256_HASH_LEN || userId <= 0) {
        LNN_LOGE(LNN_STATE, "GetOhosAccount get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    char *accountInfo = nullptr;
    uint32_t size = 0;
    int32_t ret = GetOsAccountIdByUserId(userId, &accountInfo, &size);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get osAccountId fail");
        return ret;
    }
    if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(accountInfo), size,
        reinterpret_cast<unsigned char *>(accountHash)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "GetOhosAccount generate str hash fail");
        SoftBusFree(accountInfo);
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    SoftBusFree(accountInfo);
    return SOFTBUS_OK;
}

void LnnAccoutIdStatusSet(int64_t accountId)
{
    if (!g_accountIdInited) {
        if (accountId != 0) {
            LnnInitDeviceInfoStatusSet(LEDGER_INFO_ACCOUNTID, DEPS_STATUS_SUCCESS);
            g_accountIdInited = true;
        } else {
            LnnInitDeviceInfoStatusSet(LEDGER_INFO_ACCOUNTID, DEPS_STATUS_FAILED);
        }
    }
}

int32_t LnnInitOhosAccount(void)
{
    int64_t accountId = 0;
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    char accountUid[ACCOUNT_UID_STR_LEN] = {0};
    uint32_t size = 0;

    if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(DEFAULT_USER_ID.c_str()),
        DEFAULT_USER_ID.length(), reinterpret_cast<unsigned char *>(accountHash)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "InitOhosAccount generate default str hash fail");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    if (IsSameAccountGroupDevice()) {
        (void)LnnJudgeDeviceTypeAndGetOsAccountInfo(accountHash, SHA_256_HASH_LEN);
        if (GetCurrentAccount(&accountId) == SOFTBUS_OK) {
            (void)LnnSetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, accountId);
        }
    }
    if (GetOsAccountUid(accountUid, ACCOUNT_UID_STR_LEN, &size) == SOFTBUS_OK) {
        LnnSetLocalStrInfo(STRING_KEY_ACCOUNT_UID, accountUid);
    } else {
        LnnSetLocalStrInfo(STRING_KEY_ACCOUNT_UID, DEFAULT_ACCOUNT_UID.c_str());
    }
    LnnAccoutIdStatusSet(accountId);
    LNN_LOGI(LNN_STATE, "init accountHash. accountHash[0]=%{public}02X, accountHash[1]=%{public}02X",
        accountHash[0], accountHash[1]);
    return LnnSetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN);
}

static void AccountUpdateProcess(uint8_t *localAccountHash, uint8_t *accountHash, int64_t accountId,
    UpdateAccountReason reason)
{
    if (localAccountHash == nullptr || accountHash == nullptr) {
        LNN_LOGE(LNN_STATE, "invalid param");
        return;
    }
    LnnAccoutIdStatusSet(accountId);

    char accountUid[ACCOUNT_UID_STR_LEN] = {0};
    uint32_t size = 0;
    ClearAuthLimitMap();
    ClearLnnBleReportExtraMap();
    ClearPcRestrictMap();
    LNN_LOGI(LNN_STATE,
        "accountHash update. localAccountHash=[%{public}02X, %{public}02X], accountHash=[%{public}02X, %{public}02X], "
        "reason:%{public}d", localAccountHash[0], localAccountHash[1], accountHash[0], accountHash[1], reason);
    LnnSetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN);
    LnnSetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, accountId);
    if (GetOsAccountUid(accountUid, ACCOUNT_UID_STR_LEN, &size) == SOFTBUS_OK) {
        LnnSetLocalStrInfo(STRING_KEY_ACCOUNT_UID, accountUid);
    } else {
        LnnSetLocalStrInfo(STRING_KEY_ACCOUNT_UID, DEFAULT_ACCOUNT_UID.c_str());
    }
    DiscDeviceInfoChanged(TYPE_ACCOUNT);
    LnnNotifyDeviceInfoChanged(SOFTBUS_LOCAL_DEVICE_INFO_ACOUNT_CHANGED);
    if (reason == UPDATE_HEARTBEAT || reason == UPDATE_USER_SWITCH ||
        (reason == UPDATE_ACCOUNT_ONLY && IsSupportMcuFeaturePacked())) {
        LnnUpdateHeartbeatInfo(UPDATE_HB_ACCOUNT_INFO);
        DfxRecordTriggerTime(UPDATE_ACCOUNT, EVENT_STAGE_LNN_UPDATE_ACCOUNT);
    }
}

static int32_t GenerateDefaultAccountStrHash(unsigned char *accountHash, uint32_t len)
{
    if (len != SHA_256_HASH_LEN) {
        LNN_LOGE(LNN_STATE, "get invalid param length");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(DEFAULT_USER_ID.c_str()),
        DEFAULT_USER_ID.length(), reinterpret_cast<unsigned char *>(accountHash));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "OnAccountChanged generate default str hash fail");
        return ret;
    }
    return SOFTBUS_OK;
}

void LnnUpdateOhosAccount(UpdateAccountReason reason)
{
    int64_t accountId = 0;
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    uint8_t localAccountHash[SHA_256_HASH_LEN] = {0};
    bool isDefaultAccount = false;

    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "OnAccountChanged get local account hash fail");
        return;
    }
    if (LnnJudgeDeviceTypeAndGetOsAccountInfo(accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGW(LNN_STATE, "OnAccountChanged get account account hash fail");
        isDefaultAccount = true;
        if (GenerateDefaultAccountStrHash(accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
            return;
        }
    }
    if ((reason == UPDATE_ACCOUNT_ONLY || reason == UPDATE_HEARTBEAT) &&
        memcmp(accountHash, localAccountHash, SHA_256_HASH_LEN) == EOK) {
        LNN_LOGW(LNN_STATE, "accountHash not changed, accountHash=[%{public}02X, %{public}02X]",
            accountHash[0], accountHash[1]);
        return;
    }
    if (!IsSameAccountGroupDevice() && !isDefaultAccount) {
        if (GenerateDefaultAccountStrHash(accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
            return;
        }
        AccountUpdateProcess(localAccountHash, accountHash, accountId, reason);
        LNN_LOGE(LNN_STATE, "not have same account group, update default accountId");
        return;
    }
    if (GetCurrentAccount(&accountId) == SOFTBUS_OK) {
        (void)LnnSetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, accountId);
    }
    AccountUpdateProcess(localAccountHash, accountHash, accountId, reason);
}

void LnnOnOhosAccountLogout(void)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    char accountUid[ACCOUNT_UID_STR_LEN] = {0};
    uint32_t size = 0;

    (void)LnnSetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, 0);
    if (SoftBusGenerateStrHash(reinterpret_cast<const unsigned char *>(DEFAULT_USER_ID.c_str()),
        DEFAULT_USER_ID.length(), reinterpret_cast<unsigned char *>(accountHash)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "OnAccountChanged generate default str hash fail");
        return;
    }
    LNN_LOGI(LNN_STATE,
        "accountHash changed. accountHash=[%{public}02X, %{public}02X]", accountHash[0], accountHash[1]);
    LnnSetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN);
    if (GetOsAccountUid(accountUid, ACCOUNT_UID_STR_LEN, &size) == SOFTBUS_OK) {
        LnnSetLocalStrInfo(STRING_KEY_ACCOUNT_UID, accountUid);
    } else {
        LnnSetLocalStrInfo(STRING_KEY_ACCOUNT_UID, DEFAULT_ACCOUNT_UID.c_str());
    }
    DiscDeviceInfoChanged(TYPE_ACCOUNT);
    LnnNotifyDeviceInfoChanged(SOFTBUS_LOCAL_DEVICE_INFO_ACOUNT_CHANGED);
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
