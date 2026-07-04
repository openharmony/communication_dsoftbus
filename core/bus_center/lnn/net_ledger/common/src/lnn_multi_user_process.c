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

#include "lnn_multi_user_process.h"

#include <securec.h>
#include <stddef.h>
#include <stdlib.h>

#include "bus_center_manager.h"
#include "g_enhance_lnn_func.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_async_callback_utils.h"
#include "lnn_data_cloud_sync.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_local_net_ledger.h"
#include "lnn_local_user_info.h"
#include "lnn_log.h"
#include "lnn_node_info.h"
#include "lnn_ohos_account.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

int32_t PackUserInfoToJsonInner(cJSON *json, const UserInfo *userInfo)
{
    if (userInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnPackCloudSyncUserInfoPacked(json, userInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "pack cloud sync info fail");
        return SOFTBUS_KV_CLOUD_SYNC_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t LnnMultiUserAllDataSyncToDB(NodeInfo *info, const UserInfo *userInfo, bool isAckSeq, char *peerudid)
{
    if (info == NULL || userInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (userInfo->accountId <= 0) {
        LNN_LOGI(LNN_LEDGER, "multi user ledger accountId is null, all data no need sync to cloud");
        return SOFTBUS_KV_CLOUD_DISABLED;
    }
    bool isMainScreenUserId = (userInfo->displayId == MAIN_SCREEN_USER_TYPE) ? true : false;
    int32_t ret = SyncLedgerInfoToCloud(info, userInfo, isAckSeq, peerudid, isMainScreenUserId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "sync foreground user to cloud failed, userId=%{public}d", userInfo->userId);
        return ret;
    }
    return SOFTBUS_OK;
}

static void ProcessMultiforegroundUserSyncToDB(void *para)
{
    ForegroundUserSyncInfo *userSyncInfo = (ForegroundUserSyncInfo *)para;
    (void)LnnMultiUserAllDataSyncToDB(&userSyncInfo->nodeInfo, &userSyncInfo->userInfo, false, NULL);
    SoftBusFree(userSyncInfo);
}

static int32_t LnnAsyncCallMultiUserLedgerSync(const NodeInfo *info, const UserInfo *userInfo)
{
    if (info == NULL || userInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ForegroundUserSyncInfo *data = (ForegroundUserSyncInfo *)SoftBusCalloc(sizeof(ForegroundUserSyncInfo));
    if (data == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc mem fail!");
        return SOFTBUS_MALLOC_ERR;
    }
    data->nodeInfo = *info;
    data->userInfo = *userInfo;
    int32_t rc = LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_LNN), ProcessMultiforegroundUserSyncToDB, data);
    if (rc != SOFTBUS_OK) {
        SoftBusFree(data);
        return rc;
    }
    return rc;
}

int32_t LnnAsyncCallMultiUserAllDataSyncToDB(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    const SoftBusList *localUserList = LnnGetLocalUserLedger();
    if (localUserList == NULL) {
        LNN_LOGE(LNN_LEDGER, "local user list is null, please check user list");
        return SOFTBUS_NETWORK_GET_LOCAL_LEDGER_FAILED;
    }
    if (SoftBusMutexLock(&localUserList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock local user list failed, please check lock");
        return SOFTBUS_LOCK_ERR;
    }
    UserInfo usersToSync[FOREGROUND_ACCOUNT_MAX_SIZE] = {0};
    uint32_t syncCount = 0;
    UserStorageInfo *user = NULL;
    UserStorageInfo *userNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(user, userNext, &localUserList->list, UserStorageInfo, node) {
        if (syncCount >= FOREGROUND_ACCOUNT_MAX_SIZE) {
            LNN_LOGW(LNN_LEDGER, "user count exceed");
            continue;
        }
        if (memcpy_s(&usersToSync[syncCount], sizeof(UserInfo), &user->info,
            sizeof(UserInfo)) == EOK) {
            syncCount++;
        } else {
            LNN_LOGE(LNN_LEDGER, "copy user info failed, please check user info");
        }
    }
    (void)SoftBusMutexUnlock(&localUserList->lock);
    for (uint32_t i = 0; i < syncCount; i++) {
        if (LnnAsyncCallMultiUserLedgerSync(info, &usersToSync[i]) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "sync to cloud failed, please sync again");
        }
    }
    return SOFTBUS_OK;
}

static int32_t ProcessSingleUser(int32_t userId, int32_t mainScreenUserId, const NodeInfo *nodeInfo)
{
    int64_t accountId = 0;
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    int32_t ret = LnnGetAccountIdByUserId(userId, &accountId, accountHash, SHA_256_HASH_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get accountId failed, userId=%{public}d, please check userId", userId);
        return ret;
    }
    UserInfo existUser;
    (void)memset_s(&existUser, sizeof(UserInfo), 0, sizeof(UserInfo));
    ret = LnnGetUserInfoSafe(userId, &existUser);
    if (ret == SOFTBUS_OK && existUser.accountId != 0) {
        LNN_LOGI(LNN_LEDGER, "user already exists in local ledger, skip, userId=%{public}d", userId);
        return SOFTBUS_ALREADY_EXISTED;
    }
    uint64_t displayId = (userId == mainScreenUserId) ? MAIN_SCREEN_USER_TYPE : OTHER_SCREEN_USER_TYPE;
    UserInfo userInfo = {
        .userId = userId,
        .accountId = accountId,
        .displayId = displayId,
        .updateTimestamp = SoftBusGetSysTimeMs()
    };
    if (memcpy_s(userInfo.accountHash, SHA_256_HASH_LEN, accountHash, SHA_256_HASH_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s accountHash failed");
        return SOFTBUS_MEM_ERR;
    }
    ret = LnnAddLocalUserInfo(&userInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "add user to ledger failed, userId=%{public}d, ret=%{public}d", userId, ret);
        return ret;
    }
    ret = LnnSaveLocalUserInfoPacked();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "save local user info failed, ret=%{public}d", ret);
    }
    ret = LnnMultiUserAllDataSyncToDB(nodeInfo, &userInfo, false, NULL);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "sync user to cloud failed, userId=%{public}d", userId);
        return ret;
    }
    LNN_LOGI(LNN_LEDGER, "sync user to cloud successful, userId=%{public}d", userId);
    return SOFTBUS_OK;
}

int32_t HbMultiUserHandleLogin(void)
{
    int32_t mainScreenUserId = JudgeDeviceTypeAndGetOsAccountIds();
    if (mainScreenUserId < 0) {
        LNN_LOGE(LNN_LEDGER, "invalid mainScreenUserId=%{public}d", mainScreenUserId);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t *userIds = NULL;
    uint32_t userIdsLen = 0;
    if (GetAllForegroundAccountIds(&userIds, &userIdsLen) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get all foreground users failed, please check foreground accounts");
        return SOFTBUS_NETWORK_QUERY_ACCOUNT_ID_FAILED;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetLocalNodeInfoSafe(&nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local node info failed, please check local node info");
        SoftBusFree(userIds);
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    for (uint32_t i = 0; i < userIdsLen; i++) {
        int32_t ret = ProcessSingleUser(userIds[i], mainScreenUserId, &nodeInfo);
        if (ret == SOFTBUS_ALREADY_EXISTED) {
            continue;
        }
        if (ret != SOFTBUS_OK) {
            LNN_LOGW(LNN_LEDGER, "process single user failed, userId=%{public}d, ret=%{public}d", userIds[i], ret);
        }
    }
    SoftBusFree(userIds);
    return SOFTBUS_OK;
}

int32_t HbMultiUserHandleLogout(void)
{
    return LnnResetLogoutUserInfo();
}

void RestoreLocalUserInfo(void)
{
    LNN_LOGI(LNN_LEDGER, "restore local user info enter");
    if (LnnLoadLocalUserInfoPacked() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "load local user info fail");
    }
}

void HbCheckSingleUser(int32_t userId)
{
    UserInfo ledgerInfo;
    int64_t sysAccountId = 0;
    uint8_t sysAccountHash[SHA_256_HASH_LEN] = {0};

    if (LnnGetUserInfoSafe(userId, &ledgerInfo) != SOFTBUS_OK) {
        return;
    }
    if (LnnGetAccountIdByUserId(userId, &sysAccountId, sysAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "get system accountId failed, assume not logged in, userId=%{public}d", userId);
        // sysAccountId 已初始化为 0，无需再赋值
    }

    // 场景1：台账残留旧账号（已登出但台账未清），补清理
    if (ledgerInfo.accountId > 0 && ledgerInfo.accountId != sysAccountId) {
        if (LnnClearLocalUserAccountByUserId(userId, ledgerInfo.displayId == MAIN_SCREEN_USER_TYPE) != SOFTBUS_OK) {
            LNN_LOGW(LNN_LEDGER, "clear user account failed, userId=%{public}d", userId);
        }
    }

    // 场景2：系统侧已有新账号但台账没有，主动刷新（容错 LOGIN 丢失）
    if (sysAccountId > 0 && ledgerInfo.accountId != sysAccountId) {
        int32_t mainScreenUserId = JudgeDeviceTypeAndGetOsAccountIds();
        NodeInfo nodeInfo;
        (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
        if (LnnGetLocalNodeInfoSafe(&nodeInfo) == SOFTBUS_OK) {
            ProcessSingleUser(userId, mainScreenUserId, &nodeInfo);
        }
    }
}

void HbCheckAllForegroundUsers(void)
{
    int32_t *userIds = NULL;
    uint32_t len = 0;
    if (GetAllForegroundAccountIds(&userIds, &len) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get all foreground users failed");
        return;
    }
    for (uint32_t i = 0; i < len; i++) {
        HbCheckSingleUser(userIds[i]);
    }
    SoftBusFree(userIds);
}
