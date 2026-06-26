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

#include "lnn_distributed_user_info.h"

#include <securec.h>

#include "anonymizer.h"
#include "lnn_distributed_net_ledger_common.h"
#include "lnn_log.h"
#include "lnn_map.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

static bool g_distributedUserLedgerStatus = false;
static Map g_distributedUserMap;
static SoftBusMutex g_distributedUserLedgerLock;

typedef struct {
    char udid[UDID_BUF_LEN];
    SoftBusList *userList;
} DistributedUserInfo;

static void FreeDistributedUserInfo(DistributedUserInfo *multiUserInfo)
{
    if (multiUserInfo->userList != NULL) {
        UserStorageInfo *item = NULL;
        UserStorageInfo *next = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(item, next, &multiUserInfo->userList->list, UserStorageInfo, node) {
            ListDelete(&item->node);
            multiUserInfo->userList->cnt--;
            SoftBusFree(item);
        }
        DestroySoftBusList(multiUserInfo->userList);
        multiUserInfo->userList = NULL;
    }
}

int32_t LnnInitDistributedUserLedger(void)
{
    if (g_distributedUserLedgerStatus == true) {
        LNN_LOGI(LNN_LEDGER, "distributed user ledger already init");
        return SOFTBUS_OK;
    }
    if (SoftBusMutexInit(&g_distributedUserLedgerLock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "init distributed user mutex failed, please check mutex");
        return SOFTBUS_LOCK_ERR;
    }
    LnnMapInit(&g_distributedUserMap);
    g_distributedUserLedgerStatus = true;
    LNN_LOGI(LNN_LEDGER, "init distributed user ledger successful");
    return SOFTBUS_OK;
}

void LnnDeinitDistributedUserLedger(void)
{
    if (g_distributedUserLedgerStatus == false) {
        LNN_LOGI(LNN_LEDGER, "distributed user ledger not init");
        return;
    }
    if (SoftBusMutexLock(&g_distributedUserLedgerLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "distributed user ledger lock failed");
        return;
    }
    MapIterator *it = LnnMapInitIterator(&g_distributedUserMap);
    if (it == NULL) {
        LNN_LOGE(LNN_LEDGER, "init map iterator failed, force deinit");
        (void)SoftBusMutexUnlock(&g_distributedUserLedgerLock);
        return;
    }
    while (LnnMapHasNext(it)) {
        DistributedUserInfo *multiUserInfo = (DistributedUserInfo *)LnnMapNext(it);
        if (multiUserInfo != NULL) {
            FreeDistributedUserInfo(multiUserInfo);
        }
    }
    LnnMapDeinitIterator(it);
    LnnMapDelete(&g_distributedUserMap);
    g_distributedUserLedgerStatus = false;
    (void)SoftBusMutexUnlock(&g_distributedUserLedgerLock);
    SoftBusMutexDestroy(&g_distributedUserLedgerLock);
    LNN_LOGI(LNN_LEDGER, "deinit distributed user ledger successful");
}

void LnnRemoveUserInfoNode(const char *udid)
{
    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid is null, please check udid");
        return;
    }
    if (SoftBusMutexLock(&g_distributedUserLedgerLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "distributed user ledger lock failed, please check lock");
        return;
    }
    DistributedUserInfo *multiUserInfo = (DistributedUserInfo *)LnnMapGet(&g_distributedUserMap, udid);
    if (multiUserInfo == NULL) {
        LNN_LOGW(LNN_LEDGER, "peer udid not online");
        (void)SoftBusMutexUnlock(&g_distributedUserLedgerLock);
        return;
    }
    FreeDistributedUserInfo(multiUserInfo);
    (void)LnnMapErase(&g_distributedUserMap, udid);
    (void)SoftBusMutexUnlock(&g_distributedUserLedgerLock);

    char *anonyUdid = NULL;
    Anonymize(udid, &anonyUdid);
    LNN_LOGI(LNN_LEDGER, "delete udid=%{public}s success", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
}

static bool IsIgnoreUpdateUserToLedger(uint64_t oldTimestamp, uint64_t newTimestamp)
{
    bool isIgnore = oldTimestamp > newTimestamp;
    if (isIgnore) {
        LNN_LOGI(LNN_LEDGER,
            "ignore new user info, oldTimestamp=%{public}" PRIu64 ", newTimestamp=%{public}" PRIu64 "",
            oldTimestamp, newTimestamp);
    }
    return isIgnore;
}

static int32_t AddUserToDistributedList(SoftBusList *userList, const UserInfo *userInfo)
{
    UserStorageInfo *newUser = (UserStorageInfo *)SoftBusCalloc(sizeof(UserStorageInfo));
    if (newUser == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc newUser failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(&newUser->info, sizeof(UserInfo), userInfo, sizeof(UserInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy user info failed");
        SoftBusFree(newUser);
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&userList->list, &newUser->node);
    userList->cnt++;
    LNN_LOGI(LNN_LEDGER, "add user to distributed user ledger successful, userId=%{public}d", userInfo->userId);
    return SOFTBUS_OK;
}

static int32_t InsertNewDistributedUser(const char *udid, const UserInfo *userInfo)
{
    DistributedUserInfo newUser;
    (void)memset_s(&newUser, sizeof(DistributedUserInfo), 0, sizeof(DistributedUserInfo));
    if (strcpy_s(newUser.udid, UDID_BUF_LEN, udid) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy udid failed");
        return SOFTBUS_STRCPY_ERR;
    }
    newUser.userList = NULL;
    int32_t ret = LnnMapSet(&g_distributedUserMap, udid, &newUser, sizeof(DistributedUserInfo));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lnn map set failed, ret=%{public}d", ret);
        return SOFTBUS_NETWORK_MAP_SET_FAILED;
    }
    DistributedUserInfo *mapUser = (DistributedUserInfo *)LnnMapGet(&g_distributedUserMap, udid);
    if (mapUser == NULL) {
        LNN_LOGE(LNN_LEDGER, "userInfo not found, please check map");
        return SOFTBUS_NETWORK_MAP_GET_FAILED;
    }
    mapUser->userList = CreateSoftBusList();
    if (mapUser->userList == NULL) {
        LNN_LOGE(LNN_LEDGER, "create user list failed");
        (void)LnnMapErase(&g_distributedUserMap, udid);
        return SOFTBUS_CREATE_LIST_ERR;
    }
    ret = AddUserToDistributedList(mapUser->userList, userInfo);
    if (ret != SOFTBUS_OK) {
        DestroySoftBusList(mapUser->userList);
        mapUser->userList = NULL;
        (void)LnnMapErase(&g_distributedUserMap, udid);
        return ret;
    }
    return SOFTBUS_OK;
}

static UserStorageInfo *FindUserByUserIdAndAccountId(SoftBusList *list, int32_t userId, int64_t accountId)
{
    if (list == NULL) {
        LNN_LOGE(LNN_LEDGER, "list is null, please check list");
        return NULL;
    }
    UserStorageInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &list->list, UserStorageInfo, node) {
        if (item->info.userId == userId && item->info.accountId == accountId) {
            return item;
        }
    }
    return NULL;
}

static int32_t UpdateExistDistributedUser(DistributedUserInfo *multiUserInfo, const UserInfo *userInfo)
{
    UserStorageInfo *existUser = FindUserByUserIdAndAccountId(
        multiUserInfo->userList, userInfo->userId, userInfo->accountId);
    if (existUser != NULL) {
        if (IsIgnoreUpdateUserToLedger(existUser->info.updateTimestamp, userInfo->updateTimestamp)) {
            return SOFTBUS_OK;
        }
        if (memcpy_s(&existUser->info, sizeof(UserInfo), userInfo, sizeof(UserInfo)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "update user info failed");
            return SOFTBUS_MEM_ERR;
        }
        return SOFTBUS_OK;
    }
    return AddUserToDistributedList(multiUserInfo->userList, userInfo);
}

int32_t LnnUpdateDistributedUserInfo(const UserInfo *userInfo, const char *udid)
{
    if (userInfo == NULL || udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedUserLedgerLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "distributed user ledger lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SOFTBUS_OK;
    DistributedUserInfo *multiUserInfo = (DistributedUserInfo *)LnnMapGet(&g_distributedUserMap, udid);
    if (multiUserInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "not found, need to insert");
        ret = InsertNewDistributedUser(udid, userInfo);
    } else {
        if (multiUserInfo->userList == NULL) {
            (void)SoftBusMutexUnlock(&g_distributedUserLedgerLock);
            return SOFTBUS_INVALID_PARAM;
        }
        ret = UpdateExistDistributedUser(multiUserInfo, userInfo);
    }
    (void)SoftBusMutexUnlock(&g_distributedUserLedgerLock);
    return ret;
}
