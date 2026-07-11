/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_local_user_info.h"

#include <securec.h>
#include <stddef.h>
#include <string.h>

#include "lnn_data_cloud_sync.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_log.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

#define DEFAULT_USER_ID "0"

static SoftBusList *g_localUserLedger = NULL;

int32_t LnnInitLocalUserLedger(void)
{
    g_localUserLedger = CreateSoftBusList();
    if (g_localUserLedger == NULL) {
        LNN_LOGE(LNN_LEDGER, "create local user list failed, please check memory");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "init local user ledger successful");
    return SOFTBUS_OK;
}

void LnnDeinitLocalUserLedger(void)
{
    if (g_localUserLedger == NULL) {
        LNN_LOGI(LNN_LEDGER, "g_localUserLedger is null");
        return;
    }
    UserStorageInfo *item = NULL;
    UserStorageInfo *next = NULL;
    if (SoftBusMutexLock(&g_localUserLedger->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock local user ledger list failed, please check lock");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_localUserLedger->list, UserStorageInfo, node) {
        ListDelete(&item->node);
        g_localUserLedger->cnt--;
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_localUserLedger->lock);
    DestroySoftBusList(g_localUserLedger);
    g_localUserLedger = NULL;
    LNN_LOGI(LNN_LEDGER, "deinit local user ledger successful");
}

static UserInfo *FindUserByUserId(SoftBusList *list, int32_t userId)
{
    if (list == NULL) {
        LNN_LOGE(LNN_LEDGER, "list is null");
        return NULL;
    }
    UserStorageInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &list->list, UserStorageInfo, node) {
        if (item->info.userId == userId) {
            return &item->info;
        }
    }
    return NULL;
}

int32_t LnnAddLocalUserInfo(const UserInfo *userInfo)
{
    if (userInfo == NULL || g_localUserLedger == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_localUserLedger->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock local user list failed");
        return SOFTBUS_LOCK_ERR;
    }
    UserInfo *existUser = FindUserByUserId(g_localUserLedger, userInfo->userId);
    if (existUser != NULL && existUser->accountId == 0) {
        if (memcpy_s(existUser, sizeof(UserInfo), userInfo, sizeof(UserInfo)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "memcpy user info failed");
            (void)SoftBusMutexUnlock(&g_localUserLedger->lock);
            return SOFTBUS_MEM_ERR;
        }
        (void)SoftBusMutexUnlock(&g_localUserLedger->lock);
        LNN_LOGI(LNN_LEDGER, "update user info successful, userId=%{public}d", userInfo->userId);
        return SOFTBUS_OK;
    }
    UserStorageInfo *newUser = (UserStorageInfo *)SoftBusCalloc(sizeof(UserStorageInfo));
    if (newUser == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc user info failed");
        (void)SoftBusMutexUnlock(&g_localUserLedger->lock);
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(&newUser->info, sizeof(UserInfo), userInfo, sizeof(UserInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy user info failed");
        SoftBusFree(newUser);
        (void)SoftBusMutexUnlock(&g_localUserLedger->lock);
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&g_localUserLedger->list, &newUser->node);
    g_localUserLedger->cnt++;
    (void)SoftBusMutexUnlock(&g_localUserLedger->lock);
    LNN_LOGI(LNN_LEDGER, "add user info successful, userId=%{public}d", userInfo->userId);
    return SOFTBUS_OK;
}

int32_t LnnGetUserInfoSafe(int32_t userId, UserInfo *userInfo)
{
    if (userInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "userInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_localUserLedger == NULL) {
        LNN_LOGE(LNN_LEDGER, "g_localUserLedger is null, please check init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_localUserLedger->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock local user list failed, please check lock");
        return SOFTBUS_LOCK_ERR;
    }
    UserInfo *user = FindUserByUserId(g_localUserLedger, userId);
    if (user == NULL) {
        LNN_LOGE(LNN_LEDGER, "user not found, userId=%{public}d", userId);
        (void)SoftBusMutexUnlock(&g_localUserLedger->lock);
        return SOFTBUS_NOT_FIND;
    }
    if (memcpy_s(userInfo, sizeof(UserInfo), user, sizeof(UserInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy user info failed");
        (void)SoftBusMutexUnlock(&g_localUserLedger->lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_localUserLedger->lock);
    return SOFTBUS_OK;
}

const SoftBusList *LnnGetLocalUserLedger(void)
{
    return g_localUserLedger;
}

static int32_t GenerateDefaultAccountHash(uint8_t *accountHash, uint32_t len)
{
    if (accountHash == NULL || len != SHA_256_HASH_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusGenerateStrHash((const unsigned char *)DEFAULT_USER_ID, strlen(DEFAULT_USER_ID),
        (unsigned char *)accountHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate default str hash failed");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnResetLogoutUserInfo(void)
{
    if (g_localUserLedger == NULL) {
        LNN_LOGI(LNN_LEDGER, "g_localUserLedger is null");
        return SOFTBUS_OK;
    }
    int32_t *userIds = NULL;
    uint32_t userIdsLen = 0;
    if (GetAllForegroundAccountIds(&userIds, &userIdsLen) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get all foreground users failed, please check accounts");
        return SOFTBUS_NETWORK_QUERY_ACCOUNT_ID_FAILED;
    }
    if (SoftBusMutexLock(&g_localUserLedger->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock local user list failed");
        SoftBusFree(userIds);
        return SOFTBUS_LOCK_ERR;
    }
    UserStorageInfo *user = NULL;
    UserStorageInfo *userNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(user, userNext, &g_localUserLedger->list, UserStorageInfo, node) {
        bool isActiveUser = false;
        for (uint32_t i = 0; i < userIdsLen; i++) {
            if (user->info.userId == userIds[i]) {
                isActiveUser = true;
                break;
            }
        }
        if (!isActiveUser && user->info.accountId != 0) {
            bool isMainScreenUserId = (user->info.displayId == MAIN_SCREEN_USER_TYPE) ? true : false;
            uint32_t filterMode = (isMainScreenUserId == true) ? CLOSE_FILTER_USERID_MODE : OPEN_FILTER_USERID_MODE;
            LnnSetCloudAbility(false, filterMode);
            if (LnnDeleteSyncToDB(user->info.userId, user->info.accountId, isMainScreenUserId) != SOFTBUS_OK) {
                LNN_LOGE(LNN_LEDGER, "delete local cache failed");
            }
            user->info.accountId = 0;
            (void)GenerateDefaultAccountHash(user->info.accountHash, SHA_256_HASH_LEN);
            LNN_LOGI(LNN_LEDGER, "reset logout user successful, userId=%{public}d", user->info.userId);
        }
    }
    (void)SoftBusMutexUnlock(&g_localUserLedger->lock);
    SoftBusFree(userIds);
    return SOFTBUS_OK;
}
