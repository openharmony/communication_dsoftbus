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

#include <atomic>
#include <memory>
#include <mutex>
#include <set>
#include <unordered_map>
#include <vector>

#include "anonymizer.h"
#include "bus_center_event.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_device_info_struct.h"
#include "lnn_log.h"
#include "lnn_ohos_account_adapter.h"
#include "message_handler.h"
#include "ohos_account_kits.h"
#include "os_account_constraint_subscriber.h"
#include "os_account_manager.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "auth_hichain_adapter.h"

static const int32_t ACCOUNT_STRTOLL_BASE = 10;
static const uint64_t CONTROL_PANEL_DISPLAY_ID = 0;
static const int32_t OS_ACCOUNT_INIT_DELAY_LEN = 1000;
static const uint32_t OS_ACCOUNT_MAX_RETRY_COUNT = 10;
static const uint32_t CONSTRAINT_UPDATE_RETRY_COUNT = 10;
static const uint32_t CONSTRAINT_UPDATE_RETRY_INTERVAL_MS = 50;
#define DEFAULT_ACCOUNT_NAME "ohosAnonymousName"
#define DEFAULT_ACCOUNT_UID "ohosAnonymousUid"

static std::mutex g_constraintMutex;
static std::unordered_map<int32_t, bool> g_accountConstraintMap;
static std::atomic<bool> g_isAccountAdapterInit(false);
static std::atomic<uint32_t> g_osAccountInitRetryTimes(0);
static std::atomic<uint32_t> g_constraintUpdateRetryTimes(0);
static std::mutex g_subscriberMutex;
static std::shared_ptr<OHOS::AccountSA::OsAccountConstraintSubscriber> g_subscriber;
static constexpr const char *DISTRIBUTED_TRANSMISSION_OUTGOING_CONSTRAINT = "constraint.distributed.transmission";

int32_t GetOsAccountId(char *id, uint32_t idLen, uint32_t *len)
{
    if (id == nullptr || len == nullptr || idLen == 0) {
        LNN_LOGE(LNN_STATE, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }

    auto accountInfo = OHOS::AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (!accountInfo.first) {
        LNN_LOGE(LNN_STATE, "QueryOhosAccountInfo failed");
        return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED;
    }

    if (accountInfo.second.name_.empty()) {
        LNN_LOGE(LNN_STATE, "accountInfo uid is empty");
        return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED;
    }

    *len = accountInfo.second.name_.length();
    char *anonyUid = nullptr;
    Anonymize(accountInfo.second.name_.c_str(), &anonyUid);
    LNN_LOGI(LNN_STATE, "uid=%{public}s, len=%{public}d", AnonymizeWrapper(anonyUid), *len);
    AnonymizeFree(anonyUid);

    if (memcmp(DEFAULT_ACCOUNT_NAME, accountInfo.second.name_.c_str(), *len) == 0) {
        LNN_LOGD(LNN_STATE, "not login account");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(id, idLen, accountInfo.second.name_.c_str(), *len) != EOK) {
        LNN_LOGE(LNN_STATE, "memcpy_s uid failed, idLen=%{public}d, len=%{public}d", idLen, *len);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t GetOsAccountIdByUserId(int32_t userId, char **id, uint32_t *len)
{
    if (id == nullptr || len == nullptr || userId <= 0) {
        LNN_LOGE(LNN_STATE, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }

    auto accountInfo = OHOS::AccountSA::OhosAccountKits::GetInstance().QueryOsAccountDistributedInfo(userId);
    if (!accountInfo.first) {
        LNN_LOGE(LNN_STATE, "QueryOhosAccountInfo failed");
        return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED;
    }

    if (accountInfo.second.name_.empty()) {
        LNN_LOGE(LNN_STATE, "accountInfo uid is empty");
        return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED;
    }

    *len = accountInfo.second.name_.length();
    char *anonyUid = nullptr;
    Anonymize(accountInfo.second.name_.c_str(), &anonyUid);
    LNN_LOGI(LNN_STATE, "uid=%{public}s, len=%{public}d", AnonymizeWrapper(anonyUid), *len);
    AnonymizeFree(anonyUid);

    if (memcmp(DEFAULT_ACCOUNT_NAME, accountInfo.second.name_.c_str(), *len) == 0) {
        LNN_LOGD(LNN_STATE, "not login account");
        return SOFTBUS_MEM_ERR;
    }
    *id = static_cast<char *>(SoftBusCalloc(*len));
    if (*id == nullptr) {
        LNN_LOGE(LNN_STATE, "malloc fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(*id, *len, accountInfo.second.name_.c_str(), *len) != EOK) {
        LNN_LOGE(LNN_STATE, "memcpy_s uid failed, len=%{public}d", *len);
        SoftBusFree(*id);
        *id = nullptr;
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t GetCurrentAccount(int64_t *account)
{
    if (account == nullptr) {
        LNN_LOGE(LNN_STATE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    *account = 0;
    auto accountInfo = OHOS::AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (!accountInfo.first) {
        LNN_LOGE(LNN_STATE, "QueryOhosAccountInfo failed");
        return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED;
    }

    if (accountInfo.second.name_.empty()) {
        LNN_LOGE(LNN_STATE, "accountInfo name_ is empty");
        return SOFTBUS_OK;
    }
    char *anonyUid = nullptr;
    Anonymize(accountInfo.second.name_.c_str(), &anonyUid);
    LNN_LOGI(LNN_STATE, "name_=%{public}s", AnonymizeWrapper(anonyUid));
    AnonymizeFree(anonyUid);
    if (memcmp(DEFAULT_ACCOUNT_NAME, accountInfo.second.name_.c_str(),
        accountInfo.second.name_.length()) == 0) {
        LNN_LOGD(LNN_STATE, "not login account");
        return SOFTBUS_OK;
    }
    *account = strtoll(accountInfo.second.name_.c_str(), nullptr, ACCOUNT_STRTOLL_BASE);
    if (*account == 0) {
        LNN_LOGE(LNN_STATE, "strtoll failed");
    }

    return SOFTBUS_OK;
}

static int32_t GetActiveOsAccountIdsByDisplayId(int32_t *userId)
{
    uint64_t displayId = CONTROL_PANEL_DISPLAY_ID;
    int32_t foregroundUserId = 0;
    if (userId == nullptr) {
        LNN_LOGE(LNN_STATE, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    auto result = OHOS::AccountSA::OsAccountManager::
        GetForegroundOsAccountLocalId(static_cast<int32_t>(displayId), foregroundUserId);
    if (result != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "GetForegroundOsAccountLocalId failed, result=%{public}d", result);
        return SOFTBUS_NETWORK_QUERY_ACCOUNT_ID_FAILED;
    }
    LNN_LOGI(LNN_STATE, "account id=%{public}d", foregroundUserId);
    *userId = foregroundUserId;
    return SOFTBUS_OK;
}

int32_t GetActiveOsAccountIds(void)
{
    std::vector<int32_t> accountId;
    int32_t ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(accountId);
    if (ret != SOFTBUS_OK || accountId.empty()) {
        LNN_LOGE(LNN_STATE, "QueryActiveOsAccountIds failed");
        return SOFTBUS_NETWORK_QUERY_ACCOUNT_ID_FAILED;
    }
    LNN_LOGD(LNN_STATE, "account id=%{public}d", accountId[0]);
    return accountId[0];
}

int32_t JudgeDeviceTypeAndGetOsAccountIds(void)
{
    int32_t localDevTypeId = 0;
    int32_t userId = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId) != SOFTBUS_OK) {
        return GetActiveOsAccountIds();
    }
    if (localDevTypeId == TYPE_CAR_ID) {
        if (GetActiveOsAccountIdsByDisplayId(&userId) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "get active OsAccountIds fail");
            return SOFTBUS_NETWORK_QUERY_ACCOUNT_ID_FAILED;
        }
    } else {
        userId = GetActiveOsAccountIds();
    }
    return userId;
}

bool IsActiveOsAccountUnlocked(void)
{
    int32_t osAccountId = JudgeDeviceTypeAndGetOsAccountIds();
    if (osAccountId == SOFTBUS_NETWORK_QUERY_ACCOUNT_ID_FAILED) {
        LNN_LOGE(LNN_STATE, "accountId is invalid");
        return false;
    }
    LNN_LOGD(LNN_STATE, "current active os accountId=%{public}d", osAccountId);
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

int32_t GetOsAccountUid(char *id, uint32_t idLen, uint32_t *len)
{
    if (id == nullptr || len == nullptr || idLen == 0) {
        LNN_LOGE(LNN_STATE, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }

    auto accountInfo = OHOS::AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (!accountInfo.first) {
        LNN_LOGE(LNN_STATE, "QueryOhosAccountInfo failed");
        return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED;
    }

    if (accountInfo.second.uid_.empty()) {
        LNN_LOGE(LNN_STATE, "accountInfo uid is empty");
        return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED;
    }

    *len = accountInfo.second.uid_.length();
    char *anonyUid = nullptr;
    Anonymize(accountInfo.second.uid_.c_str(), &anonyUid);
    LNN_LOGI(LNN_STATE, "uid=%{public}s, len=%{public}d", AnonymizeWrapper(anonyUid), *len);
    AnonymizeFree(anonyUid);

    if (memcmp(DEFAULT_ACCOUNT_UID, accountInfo.second.uid_.c_str(), *len) == 0) {
        LNN_LOGE(LNN_STATE, "not login account");
        return SOFTBUS_NOT_LOGIN;
    }
    if (memcpy_s(id, idLen, accountInfo.second.uid_.c_str(), *len) != EOK) {
        LNN_LOGE(LNN_STATE, "memcpy_s uid failed, idLen=%{public}d, len=%{public}d", idLen, *len);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t GetOsAccountUidByUserId(char *id, uint32_t idLen, uint32_t *len, int32_t userId)
{
    if (id == nullptr || len == nullptr || idLen == 0 || userId <= 0) {
        LNN_LOGE(LNN_STATE, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    OHOS::AccountSA::OhosAccountInfo accountInfo;
    int32_t ret = OHOS::AccountSA::OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(userId, accountInfo);
    if (ret != OHOS::ERR_OK) {
        LNN_LOGE(LNN_STATE, "get accountInfo failed ret=%{public}d", ret);
        return ret;
    }
    if (accountInfo.uid_.empty()) {
        LNN_LOGE(LNN_STATE, "accountInfo uid is empty");
        return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED;
    }

    *len = accountInfo.uid_.length();
    char *anonyUid = nullptr;
    Anonymize(accountInfo.uid_.c_str(), &anonyUid);
    LNN_LOGI(LNN_STATE, "accountUid=%{public}s, len=%{public}u", AnonymizeWrapper(anonyUid), *len);
    AnonymizeFree(anonyUid);

    if (memcpy_s(id, idLen, accountInfo.uid_.c_str(), *len) != EOK) {
        LNN_LOGE(LNN_STATE, "memcpy_s accountUid failed, idLen=%{public}u, len=%{public}u", idLen, *len);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t GetOsAccountLocalIdFromUid(int32_t uid, int32_t *userId)
{
    if (userId == nullptr) {
        LNN_LOGE(LNN_STATE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t localId = -1;
    OHOS::ErrCode res = OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, localId);
    if (res != OHOS::ERR_OK) {
        LNN_LOGE(LNN_STATE, "get userId fail. res=%{public}d", res);
        return SOFTBUS_NETWORK_QUERY_ACCOUNT_ID_FAILED;
    }
    *userId = localId;
    return SOFTBUS_OK;
}

class LnnOsAccountConstraintSubscriber : public OHOS::AccountSA::OsAccountConstraintSubscriber {
public:
    explicit LnnOsAccountConstraintSubscriber(const std::set<std::string> &constraintSet)
        : OHOS::AccountSA::OsAccountConstraintSubscriber(constraintSet)
    {
    }

    void OnConstraintChanged(const OHOS::AccountSA::OsAccountConstraintStateData &constraintData) override;
};

void LnnOsAccountConstraintSubscriber::OnConstraintChanged(
    const OHOS::AccountSA::OsAccountConstraintStateData &constraintData)
{
    if (constraintData.constraint.empty()) {
        LNN_LOGW(LNN_STATE, "constraint data is empty, skip");
        return;
    }
    if (constraintData.constraint != DISTRIBUTED_TRANSMISSION_OUTGOING_CONSTRAINT) {
        LNN_LOGW(LNN_STATE, "unexpected constraint=%{public}s, skip",
            constraintData.constraint.c_str());
        return;
    }
    int32_t localId = constraintData.localId;
    bool newState = constraintData.isEnabled;
    bool oldState = false;
    {
        std::lock_guard<std::mutex> lock(g_constraintMutex);
        auto it = g_accountConstraintMap.find(localId);
        if (it != g_accountConstraintMap.end()) {
            oldState = it->second;
        }
        g_accountConstraintMap[localId] = newState;
    }

    LNN_LOGI(LNN_STATE, "constraint changed, localId=%{public}d, newState=%{public}d, oldState=%{public}d",
        localId, newState, oldState);
    if (oldState == newState) {
        return;
    }
    int32_t foregroundLocalId = JudgeDeviceTypeAndGetOsAccountIds();
    if (foregroundLocalId < 0) {
        LNN_LOGW(LNN_STATE, "get foreground localId failed, skip notify");
        return;
    }
    if (localId != foregroundLocalId) {
        LNN_LOGI(LNN_STATE, "localId=%{public}d is not foreground=%{public}d, skip notify",
            localId, foregroundLocalId);
        return;
    }
    LnnNotifyConstraintStateChangeEvent(newState);
}

static int32_t SubscribeOsAccountConstraintsLocked(void)
{
    std::lock_guard<std::mutex> lock(g_subscriberMutex);

    if (g_subscriber != nullptr) {
        LNN_LOGI(LNN_STATE, "os account adapter already initialized");
        return SOFTBUS_OK;
    }

    LnnUpdateConstraintMapForCurrentAccount();

    std::set<std::string> constraints;
    constraints.insert(DISTRIBUTED_TRANSMISSION_OUTGOING_CONSTRAINT);
    g_subscriber = std::make_shared<LnnOsAccountConstraintSubscriber>(constraints);
    OHOS::ErrCode err = OHOS::AccountSA::OsAccountManager::SubscribeOsAccountConstraints(g_subscriber);
    if (err != OHOS::ERR_OK) {
        LNN_LOGE(LNN_STATE, "subscribe os account constraints failed, err=%{public}d", err);
        g_subscriber = nullptr;
        return SOFTBUS_NETWORK_SUBSCRIBE_FAILED;
    }
    LNN_LOGI(LNN_STATE, "subscribe os account constraints successful");
    return SOFTBUS_OK;
}

static void LnnUpdateConstraintMapAsync(void *para)
{
    (void)para;

    int32_t currentId = GetActiveOsAccountIds();
    if (currentId < 0) {
        LNN_LOGW(LNN_STATE, "get active os account id failed, assume not constraint");
        return;
    }
    bool isEnabled = false;
    OHOS::ErrCode err = OHOS::AccountSA::OsAccountManager::CheckOsAccountConstraintEnabled(
        currentId, DISTRIBUTED_TRANSMISSION_OUTGOING_CONSTRAINT, isEnabled);
    if (err == OHOS::ERR_OK) {
        g_constraintUpdateRetryTimes.store(0);
        {
            std::lock_guard<std::mutex> constraintLock(g_constraintMutex);
            g_accountConstraintMap[currentId] = isEnabled;
        }
        LNN_LOGI(LNN_STATE, "update constraint state=%{public}d, localId=%{public}d", isEnabled, currentId);
        LnnNotifyConstraintStateChangeEvent(isEnabled);
        return;
    }
    uint32_t retryTimes = g_constraintUpdateRetryTimes.fetch_add(1) + 1;
    if (retryTimes >= CONSTRAINT_UPDATE_RETRY_COUNT) {
        LNN_LOGW(LNN_STATE, "update constraint retry count exceeded, retryTimes=%{public}u, assume disabled",
            retryTimes);
        g_constraintUpdateRetryTimes.store(0);
        return;
    }
    LNN_LOGI(LNN_STATE, "update constraint retry, retryTimes=%{public}u", retryTimes);
    int32_t ret = LnnAsyncCallbackDelayHelper(
        GetLooper(LOOP_TYPE_DEFAULT), LnnUpdateConstraintMapAsync, nullptr, CONSTRAINT_UPDATE_RETRY_INTERVAL_MS);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "async delay call fail, ret=%{public}d", ret);
        g_constraintUpdateRetryTimes.store(0);
    }
}

void LnnUpdateConstraintMapForCurrentAccount(void)
{
    int32_t ret = LnnAsyncCallbackDelayHelper(
        GetLooper(LOOP_TYPE_DEFAULT), LnnUpdateConstraintMapAsync, nullptr, 0);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "async delay call fail for constraint update, ret=%{public}d", ret);
    }
}

static void InitOsAccountAdapterAsync(void *para)
{
    (void)para;
    if (g_isAccountAdapterInit.load()) {
        LNN_LOGI(LNN_STATE, "os account adapter is already inited");
        return;
    }

    int32_t ret = SubscribeOsAccountConstraintsLocked();
    if (ret == SOFTBUS_OK) {
        g_isAccountAdapterInit.store(true);
        return;
    }

    g_osAccountInitRetryTimes.fetch_add(1);
    if (g_osAccountInitRetryTimes.load() >= OS_ACCOUNT_MAX_RETRY_COUNT) {
        LNN_LOGE(LNN_STATE, "retry count exceed limit, retryTimes=%{public}u", g_osAccountInitRetryTimes.load());
        return;
    }

    ret = LnnAsyncCallbackDelayHelper(
        GetLooper(LOOP_TYPE_DEFAULT), InitOsAccountAdapterAsync, nullptr, OS_ACCOUNT_INIT_DELAY_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "async delay call fail, ret=%{public}d", ret);
    }
}

int32_t LnnInitOsAccountAdapter(void)
{
    if (g_isAccountAdapterInit.load()) {
        LNN_LOGI(LNN_STATE, "os account adapter is already inited");
        return SOFTBUS_OK;
    }

    g_osAccountInitRetryTimes.store(0);
    int32_t ret = LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), InitOsAccountAdapterAsync, nullptr, 0);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "async delay call fail, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

void LnnClearOsAccountAdapterStatus(void)
{
    g_isAccountAdapterInit.store(false);
    g_osAccountInitRetryTimes.store(0);
}

void LnnDeinitOsAccountAdapter(void)
{
    g_isAccountAdapterInit.store(false);
    g_osAccountInitRetryTimes.store(0);
    {
        std::lock_guard<std::mutex> constraintLock(g_constraintMutex);
        g_accountConstraintMap.clear();
    }
    std::lock_guard<std::mutex> lock(g_subscriberMutex);

    if (g_subscriber != nullptr) {
        OHOS::ErrCode err = OHOS::AccountSA::OsAccountManager::UnsubscribeOsAccountConstraints(g_subscriber);
        if (err != OHOS::ERR_OK) {
            LNN_LOGE(LNN_STATE, "unsubscribe os account constraints failed, err=%{public}d", err);
        }
        g_subscriber = nullptr;
    }
}

static bool LnnIsOsAccountConstraintByLocalId(int32_t localId)
{
    if (localId < 0) {
        LNN_LOGW(LNN_STATE, "invalid localId=%{public}d, assume not constraint", localId);
        return false;
    }
    std::lock_guard<std::mutex> lock(g_constraintMutex);
    auto it = g_accountConstraintMap.find(localId);
    if (it == g_accountConstraintMap.end()) {
        return false;
    }
    return it->second;
}

bool LnnIsOsAccountConstraint(void)
{
    int32_t currentId = GetActiveOsAccountIds();
    if (currentId < 0) {
        LNN_LOGW(LNN_STATE, "get active os account id failed, assume not constraint");
        return false;
    }
    return LnnIsOsAccountConstraintByLocalId(currentId);
}
