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

#include "auth_session_key.h"

#include <securec.h>

#include "auth_common.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_session_fsm.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define SESSION_KEY_MAX_NUM   10
#define LAST_USE_THRESHOLD_MS (30 * 1000L) /* 30s */

typedef struct {
    int32_t index;
    SessionKey key;
    uint64_t lastUseTime;
    bool isAvailable;
    ListNode node;
    uint32_t type;
    uint64_t useTime[AUTH_LINK_TYPE_MAX];
    bool isOldKey;
} SessionKeyItem;

static void RemoveOldKey(SessionKeyList *list)
{
    uint32_t num = 0;
    SessionKeyItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, (const ListNode *)list, SessionKeyItem, node) {
        num++;
    }
    if (num <= SESSION_KEY_MAX_NUM) {
        return;
    }

    SessionKeyItem *oldKey = NULL;
    uint64_t oldKeyUseTime = UINT64_MAX;
    LIST_FOR_EACH_ENTRY(item, (const ListNode *)list, SessionKeyItem, node) {
        if (item->lastUseTime < oldKeyUseTime) {
            oldKeyUseTime = item->lastUseTime;
            oldKey = item;
        }
    }
    if (oldKey == NULL) {
        AUTH_LOGE(AUTH_FSM, "remove session key fail");
        return;
    }
    ListDelete(&oldKey->node);
    AUTH_LOGI(AUTH_FSM, "session key num reach max, remove the oldest, index=%{public}d, type=%{public}u",
        oldKey->index, oldKey->type);
    (void)memset_s(&oldKey->key, sizeof(SessionKey), 0, sizeof(SessionKey));
    SoftBusFree(oldKey);
}

void InitSessionKeyList(SessionKeyList *list)
{
    AUTH_CHECK_AND_RETURN_LOGE(list != NULL, AUTH_FSM, "list is NULL");
    ListInit(list);
}

static bool SessionKeyHasAuthLinkType(uint32_t authType, AuthLinkType type)
{
    return (authType & (1 << (uint32_t)type)) != 0;
}

static void SetAuthLinkType(uint32_t *authType, AuthLinkType type)
{
    *authType = (*authType) | (1 << (uint32_t)type);
}

static void ClearAuthLinkType(uint32_t *authType, AuthLinkType type)
{
    *authType = (*authType) & (~(1 << (uint32_t)type));
}

static void UpdateLatestUseTime(SessionKeyItem *item, AuthLinkType type)
{
    if (item->lastUseTime != item->useTime[type]) {
        item->useTime[type] = 0;
        return;
    }
    item->useTime[type] = 0;
    item->lastUseTime = 0;
    for (uint32_t i = AUTH_LINK_TYPE_WIFI; i < AUTH_LINK_TYPE_MAX; i++) {
        if (item->useTime[i] > item->lastUseTime) {
            item->lastUseTime = item->useTime[i];
        }
    }
}

bool CheckSessionKeyListExistType(const SessionKeyList *list, AuthLinkType type)
{
    CHECK_NULL_PTR_RETURN_VALUE(list, false);
    SessionKeyItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, list, SessionKeyItem, node) {
        if (SessionKeyHasAuthLinkType(item->type, type)) {
            return true;
        }
    }
    return false;
}

bool CheckSessionKeyListHasOldKey(const SessionKeyList *list, AuthLinkType type)
{
    CHECK_NULL_PTR_RETURN_VALUE(list, false);
    SessionKeyItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, list, SessionKeyItem, node) {
        if (SessionKeyHasAuthLinkType(item->type, type) && item->isOldKey) {
            return true;
        }
    }
    return false;
}

int32_t ClearOldKey(const SessionKeyList *list, AuthLinkType type)
{
    CHECK_NULL_PTR_RETURN_VALUE(list, SOFTBUS_INVALID_PARAM);
    SessionKeyItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, list, SessionKeyItem, node) {
        if (SessionKeyHasAuthLinkType(item->type, type) && item->isOldKey) {
            item->isOldKey = false;
        }
    }
    return SOFTBUS_OK;
}

int32_t DupSessionKeyList(const SessionKeyList *srcList, SessionKeyList *dstList)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(srcList != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "srcList is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(dstList != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "dstList is NULL");
    SessionKeyItem *item = NULL;
    SessionKeyItem *newItem = NULL;
    LIST_FOR_EACH_ENTRY(item, srcList, SessionKeyItem, node) {
        newItem = (SessionKeyItem *)DupMemBuffer((uint8_t *)item, sizeof(SessionKeyItem));
        if (newItem == NULL) {
            AUTH_LOGE(AUTH_FSM, "malloc newItem fail");
            DestroySessionKeyList(dstList);
            return SOFTBUS_MALLOC_ERR;
        }
        ListNodeInsert(dstList, &newItem->node);
    }
    return SOFTBUS_OK;
}

void DestroySessionKeyList(SessionKeyList *list)
{
    AUTH_CHECK_AND_RETURN_LOGE(list != NULL, AUTH_FSM, "list is NULL");
    SessionKeyItem *item = NULL;
    SessionKeyItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, list, SessionKeyItem, node) {
        ListDelete(&item->node);
        (void)memset_s(&item->key, sizeof(SessionKey), 0, sizeof(SessionKey));
        SoftBusFree(item);
    }
}

bool HasSessionKey(const SessionKeyList *list)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(list != NULL, false, AUTH_FSM, "list is NULL");
    return !IsListEmpty(list);
}

AuthLinkType GetSessionKeyTypeByIndex(const SessionKeyList *list, int32_t index)
{
    CHECK_NULL_PTR_RETURN_VALUE(list, AUTH_LINK_TYPE_MAX);
    SessionKeyItem *item = NULL;
    uint32_t type = 0;
    LIST_FOR_EACH_ENTRY(item, (const ListNode *)list, SessionKeyItem, node) {
        if (item->index == index) {
            type = item->type;
            break;
        }
    }
    if (type == 0) {
        return AUTH_LINK_TYPE_MAX;
    }
    for (uint32_t i = AUTH_LINK_TYPE_WIFI; i < AUTH_LINK_TYPE_MAX; i++) {
        if (SessionKeyHasAuthLinkType(type, (AuthLinkType)i)) {
            AUTH_LOGI(AUTH_FSM, "auth link type=%{public}d", i);
            return (AuthLinkType)i;
        }
    }
    return AUTH_LINK_TYPE_MAX;
}

uint64_t GetLatestAvailableSessionKeyTime(const SessionKeyList *list, AuthLinkType type)
{
    CHECK_NULL_PTR_RETURN_VALUE(list, 0);
    if (type < AUTH_LINK_TYPE_WIFI || type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_FSM, "type error");
        return 0;
    }
    SessionKeyItem *item = NULL;
    SessionKeyItem *latestKey = NULL;
    uint64_t latestTime = 0;
    LIST_FOR_EACH_ENTRY(item, (const ListNode *)list, SessionKeyItem, node) {
        if (!item->isAvailable) {
            continue;
        }
        if (item->useTime[type] > latestTime) {
            latestTime = item->useTime[type];
            latestKey = item;
        }
    }
    if (latestKey == NULL) {
        DumpSessionkeyList(list);
        return 0;
    }
    AUTH_LOGI(AUTH_FSM, "latestUseTime=%{public}" PRIu64 ", type=%{public}d, index=%{public}d, time=%{public}" PRIu64
        ", all type=%{public}u", latestKey->lastUseTime, type, latestKey->index, latestTime, latestKey->type);
    return latestTime;
}

int32_t SetSessionKeyAvailable(SessionKeyList *list, int32_t index)
{
    CHECK_NULL_PTR_RETURN_VALUE(list, SOFTBUS_INVALID_PARAM);
    SessionKeyItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, (const ListNode *)list, SessionKeyItem, node) {
        if (item->index != index) {
            continue;
        }
        if (!item->isAvailable) {
            item->isAvailable = true;
            AUTH_LOGI(AUTH_FSM, "index=%{public}d, set available", index);
        }
        return SOFTBUS_OK;
    }
    AUTH_LOGE(AUTH_FSM, "can't find sessionKey, index=%{public}d", index);
    return SOFTBUS_AUTH_SESSION_KEY_NOT_FOUND;
}

int32_t AddSessionKey(SessionKeyList *list, int32_t index, const SessionKey *key, AuthLinkType type, bool isOldKey)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(key != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "key is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(list != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "list is NULL");
    if (type < AUTH_LINK_TYPE_WIFI || type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_FSM, "type error");
        return SOFTBUS_INVALID_PARAM;
    }
    AUTH_LOGD(AUTH_FSM, "keyLen=%{public}d", key->len);
    SessionKeyItem *item = (SessionKeyItem *)SoftBusCalloc(sizeof(SessionKeyItem));
    if (item == NULL) {
        AUTH_LOGE(AUTH_FSM, "malloc SessionKeyItem fail");
        return SOFTBUS_MALLOC_ERR;
    }
    item->isAvailable = false;
    item->index = index;
    item->lastUseTime = GetCurrentTimeMs();
    item->useTime[type] = item->lastUseTime;
    item->isOldKey = isOldKey;
    SetAuthLinkType(&item->type, type);
    if (memcpy_s(&item->key, sizeof(item->key), key, sizeof(SessionKey)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "add session key fail");
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }
    ListNodeInsert((ListNode *)list, &item->node);
    RemoveOldKey(list);
    return SOFTBUS_OK;
}

int32_t GetLatestSessionKey(const SessionKeyList *list, AuthLinkType type, int32_t *index, SessionKey *key)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(list != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "list is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(index != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "index is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(key != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "key is NULL");
    if (type < AUTH_LINK_TYPE_WIFI || type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_FSM, "type error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsListEmpty((const ListNode *)list)) {
        AUTH_LOGE(AUTH_FSM, "session key list is empty");
        return SOFTBUS_LIST_EMPTY;
    }
    SessionKeyItem *item = NULL;
    SessionKeyItem *latestKey = NULL;
    uint64_t latestTime = 0;
    LIST_FOR_EACH_ENTRY(item, (const ListNode *)list, SessionKeyItem, node) {
        if (!item->isAvailable || !SessionKeyHasAuthLinkType(item->type, type)) {
            continue;
        }
        if (item->lastUseTime > latestTime) {
            latestTime = item->lastUseTime;
            latestKey = item;
        }
    }
    if (latestKey == NULL) {
        AUTH_LOGE(AUTH_FSM, "invalid session key item, type=%{public}d", type);
        DumpSessionkeyList(list);
        return SOFTBUS_AUTH_SESSION_KEY_INVALID;
    }
    if (memcpy_s(key, sizeof(SessionKey), &latestKey->key, sizeof(latestKey->key)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "copy session key fail.");
        return SOFTBUS_MEM_ERR;
    }
    latestKey->lastUseTime = GetCurrentTimeMs();
    latestKey->useTime[type] = latestKey->lastUseTime;
    *index = latestKey->index;
    AUTH_LOGI(AUTH_FSM, "get session key succ, index=%{public}d, authtype=%{public}d, keytype=%{public}u, "
        "time=%{public}" PRIu64, latestKey->index, type, latestKey->type, latestKey->lastUseTime);
    return SOFTBUS_OK;
}

int32_t SetSessionKeyAuthLinkType(const SessionKeyList *list, int32_t index, AuthLinkType type)
{
    CHECK_NULL_PTR_RETURN_VALUE(list, SOFTBUS_INVALID_PARAM);
    if (type < AUTH_LINK_TYPE_WIFI || type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_FSM, "type error");
        return SOFTBUS_INVALID_PARAM;
    }
    SessionKeyItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, (const ListNode *)list, SessionKeyItem, node) {
        if (item->index != index) {
            continue;
        }
        SetAuthLinkType(&item->type, type);
        item->lastUseTime = GetCurrentTimeMs();
        item->useTime[type] = item->lastUseTime;
        AUTH_LOGI(AUTH_FSM, "sessionKey add type, index=%{public}d, newType=%{public}d, type=%{public}u", index, type,
            item->type);
        return SOFTBUS_OK;
    }
    AUTH_LOGI(AUTH_FSM, "not found sessionKey, index=%{public}d", index);
    return SOFTBUS_AUTH_SESSION_KEY_NOT_FOUND;
}

int32_t GetSessionKeyByIndex(const SessionKeyList *list, int32_t index, AuthLinkType type, SessionKey *key)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(list != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "list is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(key != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "key is NULL");
    if (type < AUTH_LINK_TYPE_WIFI || type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_FSM, "type error");
        return SOFTBUS_INVALID_PARAM;
    }
    SessionKeyItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, (const ListNode *)list, SessionKeyItem, node) {
        if (item->index != index) {
            continue;
        }
        if (memcpy_s(key, sizeof(SessionKey), &item->key, sizeof(item->key)) != EOK) {
            AUTH_LOGE(AUTH_FSM, "get session key fail, index=%{public}d", index);
            return SOFTBUS_MEM_ERR;
        }
        item->lastUseTime = GetCurrentTimeMs();
        item->useTime[type] = item->lastUseTime;
        AUTH_LOGI(AUTH_FSM, "get session key succ, index=%{public}d, time=%{public}" PRIu64, index, item->lastUseTime);
        return SOFTBUS_OK;
    }
    AUTH_LOGE(AUTH_FSM, "session key not found, index=%{public}d", index);
    return SOFTBUS_AUTH_NOT_FOUND;
}

void RemoveSessionkeyByIndex(SessionKeyList *list, int32_t index, AuthLinkType type)
{
    AUTH_CHECK_AND_RETURN_LOGE(list != NULL, AUTH_FSM, "list is NULL");
    bool isFind = false;
    SessionKeyItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, (const ListNode *)list, SessionKeyItem, node) {
        if (item->index == index) {
            isFind = true;
            break;
        }
    }
    if (isFind) {
        ClearAuthLinkType(&item->type, type);
        if (item->type == 0) {
            AUTH_LOGI(AUTH_FSM, "Remove Session key, index=%{public}d", index);
            ListDelete(&item->node);
            SoftBusFree(item);
        } else {
            UpdateLatestUseTime(item, type);
            AUTH_LOGI(AUTH_FSM, "Remove Session key type, index=%{public}d, type=%{public}u", index, item->type);
        }
    } else {
        AUTH_LOGE(AUTH_FSM, "Remove Session key not found, index=%{public}d", index);
    }
}

void ClearSessionkeyByAuthLinkType(int64_t authId, SessionKeyList *list, AuthLinkType type)
{
    CHECK_NULL_PTR_RETURN_VOID(list);
    SessionKeyItem *item = NULL;
    SessionKeyItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, list, SessionKeyItem, node) {
        if (!SessionKeyHasAuthLinkType(item->type, type)) {
            continue;
        }
        ClearAuthLinkType(&item->type, type);
        if (item->type == 0) {
            AUTH_LOGI(AUTH_FSM, "remove sessionkey, type=%{public}d, index=%{public}d, authId=%{public}" PRId64, type,
                item->index, authId);
            ListDelete(&item->node);
            SoftBusFree(item);
        } else {
            UpdateLatestUseTime(item, type);
        }
    }
}

int32_t EncryptData(
    const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo, uint8_t *outData, uint32_t *outLen)
{
    if (list == NULL || inDataInfo == NULL || inDataInfo->inData == NULL || inDataInfo->inLen == 0 || outData == NULL ||
        *outLen < (inDataInfo->inLen + ENCRYPT_OVER_HEAD_LEN)) {
        AUTH_LOGE(AUTH_FSM, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t index = 0;
    SessionKey sessionKey;
    if (GetLatestSessionKey(list, type, &index, &sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get key fail");
        AUTH_LOGD(AUTH_FSM, "keyLen=%{public}d", sessionKey.len);
        return SOFTBUS_ENCRYPT_ERR;
    }
    /* pack key index */
    *(uint32_t *)outData = SoftBusHtoLl((uint32_t)index);
    AesGcmCipherKey cipherKey = { .keyLen = sessionKey.len };
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey.value, sessionKey.len) != EOK) {
        AUTH_LOGE(AUTH_FSM, "set key fail");
        (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    int32_t ret = SoftBusEncryptDataWithSeq(
        &cipherKey, inDataInfo->inData, inDataInfo->inLen, outData + ENCRYPT_INDEX_LEN, outLen, index);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "SoftBusEncryptDataWithSeq fail=%{public}d", ret);
        return SOFTBUS_ENCRYPT_ERR;
    }
    *outLen += ENCRYPT_INDEX_LEN;
    return SOFTBUS_OK;
}

int32_t DecryptData(
    const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo, uint8_t *outData, uint32_t *outLen)
{
    if (list == NULL || inDataInfo == NULL || inDataInfo->inData == NULL || outData == NULL ||
        inDataInfo->inLen <= ENCRYPT_OVER_HEAD_LEN || *outLen < (inDataInfo->inLen - ENCRYPT_OVER_HEAD_LEN)) {
        AUTH_LOGE(AUTH_FSM, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    /* unpack key index */
    int32_t index = (int32_t)SoftBusLtoHl(*(uint32_t *)inDataInfo->inData);
    SessionKey sessionKey;
    if (GetSessionKeyByIndex(list, index, type, &sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get key fail");
        return SOFTBUS_DECRYPT_ERR;
    }
    AesGcmCipherKey cipherKey = { .keyLen = sessionKey.len };
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey.value, sessionKey.len) != EOK) {
        AUTH_LOGE(AUTH_FSM, "set key fail");
        (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    int32_t ret = SoftBusDecryptDataWithSeq(&cipherKey, inDataInfo->inData + ENCRYPT_INDEX_LEN,
        inDataInfo->inLen - ENCRYPT_INDEX_LEN, outData, outLen, index);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "SoftBusDecryptDataWithSeq fail=%{public}d", ret);
        return SOFTBUS_DECRYPT_ERR;
    }
    return SOFTBUS_OK;
}

int32_t EncryptInner(
    const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo, uint8_t **outData, uint32_t *outLen)
{
    if (list == NULL || inDataInfo == NULL || inDataInfo->inData == NULL || inDataInfo->inLen == 0 || outData == NULL ||
        outLen == NULL) {
        AUTH_LOGE(AUTH_FSM, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t encDataLen = inDataInfo->inLen + ENCRYPT_OVER_HEAD_LEN;
    uint8_t *encData = (uint8_t *)SoftBusCalloc(encDataLen);
    if (encData == NULL) {
        AUTH_LOGE(AUTH_FSM, "malloc encrypt data fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (EncryptData(list, type, inDataInfo, encData, &encDataLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "encrypt data fail");
        SoftBusFree(encData);
        return SOFTBUS_ENCRYPT_ERR;
    }
    *outData = encData;
    *outLen = encDataLen;
    return SOFTBUS_OK;
}

int32_t DecryptInner(
    const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo, uint8_t **outData, uint32_t *outLen)
{
    if (list == NULL || inDataInfo == NULL || inDataInfo->inData == NULL ||
        inDataInfo->inLen <= ENCRYPT_OVER_HEAD_LEN || outData == NULL || outLen == NULL) {
        AUTH_LOGE(AUTH_FSM, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t decDataLen = inDataInfo->inLen - ENCRYPT_OVER_HEAD_LEN + 1; /* for '\0' */
    uint8_t *decData = (uint8_t *)SoftBusCalloc(decDataLen);
    if (decData == NULL) {
        AUTH_LOGE(AUTH_FSM, "malloc decrypt data fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (DecryptData(list, type, inDataInfo, decData, &decDataLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "decrypt data fail");
        SoftBusFree(decData);
        return SOFTBUS_DECRYPT_ERR;
    }
    *outData = decData;
    *outLen = decDataLen;
    return SOFTBUS_OK;
}

/* For Debug */
void DumpSessionkeyList(const SessionKeyList *list)
{
    AUTH_CHECK_AND_RETURN_LOGE(list != NULL, AUTH_FSM, "list is NULL");
    uint32_t keyNum = 0;
    SessionKeyItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, (const ListNode *)list, SessionKeyItem, node) {
        AUTH_LOGI(AUTH_FSM,
            "[Dump] SessionKey keyNum=%{public}d, index=%{public}d, keyLen=%{public}u, key=XX, "
            "lastUseTime=%{public}" PRIu64 ", type=%{public}u, useTime=%{public}" PRIu64
            ", %{public}" PRIu64 ", %{public}" PRIu64 ", %{public}" PRIu64 ", %{public}" PRIu64,
            keyNum, item->index, item->key.len, item->lastUseTime, item->type, item->useTime[AUTH_LINK_TYPE_WIFI],
            item->useTime[AUTH_LINK_TYPE_BR], item->useTime[AUTH_LINK_TYPE_BLE], item->useTime[AUTH_LINK_TYPE_P2P],
            item->useTime[AUTH_LINK_TYPE_ENHANCED_P2P]);
        keyNum++;
    }
    AUTH_LOGI(AUTH_FSM, "[Dump] SessionKey total num=%{public}u", keyNum);
}

static void HandleUpdateSessionKeyEvent(const void *obj)
{
    AUTH_CHECK_AND_RETURN_LOGE(obj != NULL, AUTH_FSM, "obj is NULL");
    AuthHandle authHandle = *(AuthHandle *)(obj);
    AUTH_LOGI(AUTH_FSM, "update session key begin, authId=%{public}" PRId64, authHandle.authId);
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth == NULL) {
        return;
    }
    AuthParam authInfo = {
        .authSeq = GenSeq(false),
        .requestId = AuthGenRequestId(),
        .connId = auth->connId[authHandle.type],
        .isServer = false,
        .isFastAuth = false,
    };
    if (AuthSessionStartAuth(&authInfo, &auth->connInfo[authHandle.type]) != SOFTBUS_OK) {
        AUTH_LOGI(
            AUTH_FSM, "start auth session to update session key fail, authId=%{public}" PRId64, authHandle.authId);
    }
    DelDupAuthManager(auth);
}

static int32_t RemoveUpdateSessionKeyFunc(const void *obj, void *para)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(obj != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "obj is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(para != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "para is NULL");
    int64_t authId = *(int64_t *)(obj);
    if (authId == *(int64_t *)(para)) {
        AUTH_LOGI(AUTH_FSM, "remove update session key event, authId=%{public}" PRId64, authId);
        return SOFTBUS_OK;
    }
    return SOFTBUS_INVALID_PARAM;
}

void ScheduleUpdateSessionKey(AuthHandle authHandle, uint64_t delayMs)
{
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_FSM, "authHandle type error");
        return;
    }
    RemoveAuthEvent(EVENT_UPDATE_SESSION_KEY, RemoveUpdateSessionKeyFunc, (void *)(&authHandle.authId));
    PostAuthEvent(EVENT_UPDATE_SESSION_KEY, HandleUpdateSessionKeyEvent, &authHandle, sizeof(AuthHandle), delayMs);
}

void CancelUpdateSessionKey(int64_t authId)
{
    RemoveAuthEvent(EVENT_UPDATE_SESSION_KEY, RemoveUpdateSessionKeyFunc, (void *)(&authId));
}