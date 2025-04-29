/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "auth_user_common_key.h"

#include <securec.h>
#include <stdlib.h>

#include "anonymizer.h"
#include "auth_interface.h"
#include "auth_log.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_map.h"
#include "lnn_secure_storage.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"

#define UDID_SHORT_HASH          8
#define UDID_SHORT_HASH_HEX_STR  17
#define MAP_KEY_LEN              21
#define USER_KEY_INFO_MAX        100

#define USER_KEY_MAX_INSTANCE_CNT  0x2000000

typedef struct {
    bool isUserBindLevel;
    ListNode node;
    AuthACLInfo aclInfo;
    AuthUserKeyInfo ukInfo;
} UserKeyInfo;

static SoftBusList *g_userKeyList = NULL;

int32_t AuthUserKeyInit(void)
{
    if (g_userKeyList != NULL) {
        return SOFTBUS_OK;
    }
    g_userKeyList = CreateSoftBusList();
    if (g_userKeyList == NULL) {
        AUTH_LOGE(AUTH_KEY, "create user key list fail");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    g_userKeyList->cnt = 0;
    return SOFTBUS_OK;
}

void DeinitUserKeyList(void)
{
    UserKeyInfo *item = NULL;
    UserKeyInfo *nextItem = NULL;

    if (g_userKeyList == NULL) {
        AUTH_LOGE(AUTH_KEY, "g_userKeyList is empty");
        return;
    }
    if (SoftBusMutexLock(&g_userKeyList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "deinit key list lock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_userKeyList->list, UserKeyInfo, node) {
        ListDelete(&item->node);
        (void)memset_s(item->ukInfo.deviceKey, sizeof(item->ukInfo.deviceKey), 0, sizeof(item->ukInfo.deviceKey));
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_userKeyList->lock);
    DestroySoftBusList(g_userKeyList);
    g_userKeyList = NULL;
}

static int32_t UpdateUserKeyListByAcl(const AuthACLInfo *aclInfo, const AuthUserKeyInfo *userKeyInfo)
{
    UserKeyInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_userKeyList->list, UserKeyInfo, node) {
        if (!CompareByAllAcl(aclInfo, &item->aclInfo, aclInfo->isServer == item->aclInfo.isServer)) {
            continue;
        }
        if (memcpy_s(&item->ukInfo, sizeof(AuthUserKeyInfo), (AuthUserKeyInfo *)userKeyInfo, sizeof(AuthUserKeyInfo)) !=
            EOK) {
            AUTH_LOGE(AUTH_KEY, "memcpy_s user key info fail.");
            return SOFTBUS_MEM_ERR;
        }
        AUTH_LOGI(AUTH_KEY, "get user key item, no need insert, index=%{public}d", item->ukInfo.keyIndex);
        return SOFTBUS_OK;
    }
    AUTH_LOGE(AUTH_KEY, "not find uk instance from list.");
    return SOFTBUS_AUTH_UK_CACHE_INSTANCE_NOT_FIND;
}

static int32_t UpdateUserKeyListByUkId(const AuthACLInfo *aclInfo, const AuthUserKeyInfo *userKeyInfo)
{
    UserKeyInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_userKeyList->list, UserKeyInfo, node) {
        if ((strlen(item->aclInfo.sourceUdid) != 0) || (item->ukInfo.keyIndex != userKeyInfo->keyIndex)) {
            continue;
        }
        if (memcpy_s(&item->aclInfo, sizeof(AuthACLInfo), (AuthACLInfo *)aclInfo, sizeof(AuthACLInfo)) != EOK) {
            AUTH_LOGE(AUTH_KEY, "memcpy_s acl info fail.");
            return SOFTBUS_MEM_ERR;
        }
        AUTH_LOGI(AUTH_KEY, "get user key item, no need insert, index=%{public}d", item->ukInfo.keyIndex);
        return SOFTBUS_OK;
    }
    AUTH_LOGE(AUTH_KEY, "not find uk instance from list.");
    return SOFTBUS_AUTH_UK_CACHE_INSTANCE_NOT_FIND;
}

static void ClearInValidAclFromUserKeyList(void)
{
    UserKeyInfo *item = NULL;
    UserKeyInfo *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_userKeyList->list, UserKeyInfo, node) {
        if (strlen(item->aclInfo.sourceUdid) != 0) {
            continue;
        }
        ListDelete(&item->node);
        (void)memset_s(item->ukInfo.deviceKey, sizeof(item->ukInfo.deviceKey), 0, sizeof(item->ukInfo.deviceKey));
        SoftBusFree(item);
        g_userKeyList->cnt--;
    }
}

int32_t AuthInsertUserKey(const AuthACLInfo *aclInfo, const AuthUserKeyInfo *userKeyInfo, bool isUserBindLevel)
{
    if (aclInfo == NULL || userKeyInfo == NULL) {
        AUTH_LOGE(AUTH_KEY, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_userKeyList == NULL) {
        AUTH_LOGE(AUTH_KEY, "g_userKeyList is empty");
        return SOFTBUS_NO_INIT;
    }

    PrintfAuthAclInfo(0, 0, aclInfo);
    if (SoftBusMutexLock(&g_userKeyList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "add key lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (UpdateUserKeyListByAcl(aclInfo, userKeyInfo) == SOFTBUS_OK ||
        UpdateUserKeyListByUkId(aclInfo, userKeyInfo) == SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_userKeyList->lock);
        return SOFTBUS_OK;
    }
    if (g_userKeyList->cnt > USER_KEY_MAX_INSTANCE_CNT) {
        AUTH_LOGE(AUTH_KEY, "user key instance count over max limit");
        ClearInValidAclFromUserKeyList();
        if (g_userKeyList->cnt > USER_KEY_MAX_INSTANCE_CNT) {
            (void)SoftBusMutexUnlock(&g_userKeyList->lock);
            return SOFTBUS_AUTH_UK_CACHE_INSTANCE_FULL;
        }
    }
    UserKeyInfo *keyInfo = NULL;
    keyInfo = (UserKeyInfo *)SoftBusCalloc(sizeof(UserKeyInfo));
    if (keyInfo == NULL) {
        AUTH_LOGE(AUTH_KEY, "user key info calloc err");
        (void)SoftBusMutexUnlock(&g_userKeyList->lock);
        return SOFTBUS_MALLOC_ERR;
    }
    keyInfo->isUserBindLevel = isUserBindLevel;
    keyInfo->aclInfo = *aclInfo;
    keyInfo->ukInfo = *userKeyInfo;
    ListInit(&keyInfo->node);
    ListAdd(&g_userKeyList->list, &keyInfo->node);
    g_userKeyList->cnt++;
    AUTH_LOGI(AUTH_KEY, "add userkey succ, index=%{public}d, bindlevel=%{public}d", keyInfo->ukInfo.keyIndex,
        keyInfo->isUserBindLevel);
    (void)SoftBusMutexUnlock(&g_userKeyList->lock);
    return SOFTBUS_OK;
}

void DelUserKeyByNetworkId(char *networkId)
{
    if (g_userKeyList == NULL || networkId == NULL) {
        AUTH_LOGE(AUTH_KEY, "invalid param");
        return;
    }
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "get remote node info fail");
        return;
    }
    char *peerUdid = info.deviceInfo.deviceUdid;
    UserKeyInfo *item = NULL;
    UserKeyInfo *nextItem = NULL;
    char *anonyUdid = NULL;
    Anonymize(peerUdid, &anonyUdid);
    if (SoftBusMutexLock(&g_userKeyList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "user key lock fail, anonyUdid=%{public}s", AnonymizeWrapper(anonyUdid));
        AnonymizeFree(anonyUdid);
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_userKeyList->list, UserKeyInfo, node) {
        if ((item->aclInfo.isServer && strcmp(item->aclInfo.sinkUdid, peerUdid) != 0) ||
            (!item->aclInfo.isServer && strcmp(item->aclInfo.sourceUdid, peerUdid) != 0)) {
            continue;
        }
        AUTH_LOGI(AUTH_KEY, "clear acl info by udid, index=%{public}d, anonyUdid=%{public}s", item->ukInfo.keyIndex,
            AnonymizeWrapper(anonyUdid));
        (void)memset_s(&item->aclInfo, sizeof(item->aclInfo), 0, sizeof(item->aclInfo));
    }
    AnonymizeFree(anonyUdid);
    (void)SoftBusMutexUnlock(&g_userKeyList->lock);
}

int32_t GetUserKeyInfoDiffAccountWithUserLevel(const AuthACLInfo *aclInfo, AuthUserKeyInfo *userKeyInfo)
{
    if (aclInfo == NULL || userKeyInfo == NULL) {
        AUTH_LOGE(AUTH_KEY, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_userKeyList == NULL) {
        AUTH_LOGE(AUTH_KEY, "g_userKeyList is empty");
        return SOFTBUS_NO_INIT;
    }
    const UserKeyInfo *item = NULL;

    if (SoftBusMutexLock(&g_userKeyList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "get user key lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_userKeyList->list, UserKeyInfo, node) {
        if (!item->isUserBindLevel ||
            !CompareByAclDiffAccountWithUserLevel(
                aclInfo, &item->aclInfo, aclInfo->isServer == item->aclInfo.isServer)) {
            continue;
        }
        if (memcpy_s(userKeyInfo, sizeof(AuthUserKeyInfo), &item->ukInfo, sizeof(AuthUserKeyInfo)) != EOK) {
            (void)SoftBusMutexUnlock(&g_userKeyList->lock);
            AUTH_LOGE(AUTH_KEY, "memcpy_s user key info fail.");
            return SOFTBUS_MEM_ERR;
        }
        AUTH_LOGI(AUTH_KEY, "get user key item, no need insert, index=%{public}d", item->ukInfo.keyIndex);
        (void)SoftBusMutexUnlock(&g_userKeyList->lock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_userKeyList->lock);
    AUTH_LOGE(AUTH_KEY, "user key not found.");
    return SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND;
}

int32_t GetUserKeyInfoDiffAccount(const AuthACLInfo *aclInfo, AuthUserKeyInfo *userKeyInfo)
{
    if (aclInfo == NULL || userKeyInfo == NULL) {
        AUTH_LOGE(AUTH_KEY, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_userKeyList == NULL) {
        AUTH_LOGE(AUTH_KEY, "g_userKeyList is empty");
        return SOFTBUS_NO_INIT;
    }
    const UserKeyInfo *item = NULL;

    if (SoftBusMutexLock(&g_userKeyList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "get user key lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_userKeyList->list, UserKeyInfo, node) {
        if (!CompareByAclDiffAccount(aclInfo, &item->aclInfo, aclInfo->isServer == item->aclInfo.isServer)) {
            continue;
        }
        if (memcpy_s(userKeyInfo, sizeof(AuthUserKeyInfo), &item->ukInfo, sizeof(AuthUserKeyInfo)) != EOK) {
            (void)SoftBusMutexUnlock(&g_userKeyList->lock);
            AUTH_LOGE(AUTH_KEY, "memcpy_s user key info fail.");
            return SOFTBUS_MEM_ERR;
        }
        AUTH_LOGI(AUTH_KEY, "get user key item, no need insert, index=%{public}d", item->ukInfo.keyIndex);
        (void)SoftBusMutexUnlock(&g_userKeyList->lock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_userKeyList->lock);
    AUTH_LOGE(AUTH_KEY, "user key not found.");
    return SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND;
}

int32_t GetUserKeyInfoSameAccount(const AuthACLInfo *aclInfo, AuthUserKeyInfo *userKeyInfo)
{
    if (aclInfo == NULL || userKeyInfo == NULL) {
        AUTH_LOGE(AUTH_KEY, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_userKeyList == NULL) {
        AUTH_LOGE(AUTH_KEY, "g_userKeyList is empty");
        return SOFTBUS_NO_INIT;
    }
    const UserKeyInfo *item = NULL;

    if (SoftBusMutexLock(&g_userKeyList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "get user key lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_userKeyList->list, UserKeyInfo, node) {
        if (!CompareByAclSameAccount(aclInfo, &item->aclInfo, aclInfo->isServer == item->aclInfo.isServer)) {
            continue;
        }
        if (memcpy_s(userKeyInfo, sizeof(AuthUserKeyInfo), &item->ukInfo, sizeof(AuthUserKeyInfo)) != EOK) {
            (void)SoftBusMutexUnlock(&g_userKeyList->lock);
            AUTH_LOGE(AUTH_KEY, "memcpy_s user key info fail.");
            return SOFTBUS_MEM_ERR;
        }
        AUTH_LOGI(AUTH_KEY, "get user key item, no need insert, index=%{public}d", item->ukInfo.keyIndex);
        (void)SoftBusMutexUnlock(&g_userKeyList->lock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_userKeyList->lock);
    AUTH_LOGE(AUTH_KEY, "user key not found");
    return SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND;
}

int32_t GetUserKeyByUkId(int32_t sessionKeyId, uint8_t *uk, uint32_t ukLen)
{
    if (uk == NULL || g_userKeyList == NULL) {
        AUTH_LOGE(AUTH_KEY, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    const UserKeyInfo *item = NULL;

    if (SoftBusMutexLock(&g_userKeyList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "get user key lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_userKeyList->list, UserKeyInfo, node) {
        if (item->ukInfo.keyIndex != sessionKeyId) {
            continue;
        }
        if (ukLen < item->ukInfo.keyLen || memcpy_s(uk, ukLen, item->ukInfo.deviceKey, item->ukInfo.keyLen) != EOK) {
            (void)SoftBusMutexUnlock(&g_userKeyList->lock);
            AUTH_LOGE(AUTH_KEY, "memcpy_s user key fail.");
            return SOFTBUS_MEM_ERR;
        }
        AUTH_LOGI(AUTH_KEY, "get user key item, no need insert, index=%{public}d", item->ukInfo.keyIndex);
        (void)SoftBusMutexUnlock(&g_userKeyList->lock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_userKeyList->lock);
    AUTH_LOGE(AUTH_KEY, "user key not found.");
    return SOFTBUS_CHANNEL_AUTH_KEY_NOT_FOUND;
}