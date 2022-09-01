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
#include "auth_manager.h"
#include "auth_session_fsm.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define SESSION_KEY_MAX_NUM 10
#define LAST_USE_THRESHOLD_MS (30 * 1000L) /* 30s */

typedef struct {
    int32_t index;
    SessionKey key;
    uint64_t lastUseTime;
    ListNode node;
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
    item = LIST_ENTRY(GET_LIST_HEAD(list), SessionKeyItem, node);
    ListDelete(&item->node);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "session key num reach max, remove the oldest, index=%d", item->index);
    (void)memset_s(&item->key, sizeof(SessionKey), 0, sizeof(SessionKey));
    SoftBusFree(item);
}

void InitSessionKeyList(SessionKeyList *list)
{
    CHECK_NULL_PTR_RETURN_VOID(list);
    ListInit(list);
}

int32_t DupSessionKeyList(const SessionKeyList *srcList, SessionKeyList *dstList)
{
    CHECK_NULL_PTR_RETURN_VALUE(srcList, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(dstList, SOFTBUS_INVALID_PARAM);
    SessionKeyItem *item = NULL;
    SessionKeyItem *newItem = NULL;
    LIST_FOR_EACH_ENTRY(item, srcList, SessionKeyItem, node) {
        newItem = (SessionKeyItem *)DupMemBuffer((uint8_t *)item, sizeof(SessionKeyItem));
        if (newItem == NULL) {
            DestroySessionKeyList(dstList);
            return SOFTBUS_MALLOC_ERR;
        }
        ListTailInsert(dstList, &newItem->node);
    }
    return SOFTBUS_OK;
}

void DestroySessionKeyList(SessionKeyList *list)
{
    CHECK_NULL_PTR_RETURN_VOID(list);
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
    CHECK_NULL_PTR_RETURN_VALUE(list, false);
    return !IsListEmpty(list);
}

int32_t AddSessionKey(SessionKeyList *list, int32_t index, const SessionKey *key)
{
    CHECK_NULL_PTR_RETURN_VALUE(key, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(list, SOFTBUS_INVALID_PARAM);
    SessionKeyItem *item = SoftBusMalloc(sizeof(SessionKeyItem));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "malloc SessionKeyItem fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    item->index = index;
    item->lastUseTime = GetCurrentTimeMs();
    if (memcpy_s(&item->key, sizeof(item->key), key, sizeof(SessionKey)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "add session key fail.");
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }
    ListTailInsert((ListNode *)list, &item->node);
    RemoveOldKey(list);
    return SOFTBUS_OK;
}

int32_t GetLatestSessionKey(const SessionKeyList *list, int32_t *index, SessionKey *key)
{
    CHECK_NULL_PTR_RETURN_VALUE(list, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(index, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(key, SOFTBUS_INVALID_PARAM);
    if (IsListEmpty((const ListNode *)list)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "session key list is empty.");
        return SOFTBUS_ERR;
    }
    SessionKeyItem *item = LIST_ENTRY(GET_LIST_TAIL((const ListNode *)list), SessionKeyItem, node);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid session key item.");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(key, sizeof(SessionKey), &item->key, sizeof(item->key)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy session key fail.");
        return SOFTBUS_MEM_ERR;
    }
    item->lastUseTime = GetCurrentTimeMs();
    *index = item->index;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "get session key succ, index=%d.", item->index);
    return SOFTBUS_OK;
}

int32_t GetSessionKeyByIndex(const SessionKeyList *list, int32_t index, SessionKey *key)
{
    CHECK_NULL_PTR_RETURN_VALUE(list, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(key, SOFTBUS_INVALID_PARAM);
    SessionKeyItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, (const ListNode *)list, SessionKeyItem, node) {
        if (item->index != index) {
            continue;
        }
        if (memcpy_s(key, sizeof(SessionKey), &item->key, sizeof(item->key)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get session key fail, index=%d.", index);
            return SOFTBUS_MEM_ERR;
        }
        item->lastUseTime = GetCurrentTimeMs();
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "get session key succ, index=%d.", index);
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "session key not found, index=%d.", index);
    return SOFTBUS_ERR;
}

int32_t EncryptData(const SessionKeyList *list, const uint8_t *inData, uint32_t inLen,
    uint8_t *outData, uint32_t *outLen)
{
    if (list == NULL || inData == NULL || inLen == 0 || outData == NULL ||
        *outLen < (inLen + ENCRYPT_OVER_HEAD_LEN)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t index = 0;
    SessionKey sessionKey;
    if (GetLatestSessionKey(list, &index, &sessionKey) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get key fail.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    /* pack key index */
    *(uint32_t *)outData = SoftBusHtoLl((uint32_t)index);
    AesGcmCipherKey cipherKey = {.keyLen = sessionKey.len};
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey.value, sessionKey.len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "set key fail.");
        (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    int32_t ret = SoftBusEncryptDataWithSeq(&cipherKey, inData, inLen, outData + ENCRYPT_INDEX_LEN, outLen, index);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusEncryptDataWithSeq fail(=%d).", ret);
        return SOFTBUS_ENCRYPT_ERR;
    }
    *outLen += ENCRYPT_INDEX_LEN;
    return SOFTBUS_OK;
}

int32_t DecryptData(const SessionKeyList *list, const uint8_t *inData, uint32_t inLen,
    uint8_t *outData, uint32_t *outLen)
{
    if (list == NULL || inData == NULL || outData == NULL || inLen <= ENCRYPT_OVER_HEAD_LEN ||
        *outLen < (inLen - ENCRYPT_OVER_HEAD_LEN)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    /* unpack key index */
    int32_t index = (int32_t)SoftBusLtoHl(*(uint32_t *)inData);
    SessionKey sessionKey;
    if (GetSessionKeyByIndex(list, index, &sessionKey) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get key fail.");
        return SOFTBUS_DECRYPT_ERR;
    }
    AesGcmCipherKey cipherKey = {.keyLen = sessionKey.len};
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey.value, sessionKey.len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "set key fail.");
        (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    int32_t ret = SoftBusDecryptDataWithSeq(&cipherKey, inData + ENCRYPT_INDEX_LEN, inLen - ENCRYPT_INDEX_LEN,
        outData, outLen, index);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusDecryptDataWithSeq fail(=%d).", ret);
        return SOFTBUS_DECRYPT_ERR;
    }
    return SOFTBUS_OK;
}

int32_t EncryptInner(const SessionKeyList *list, const uint8_t *inData, uint32_t inLen,
    uint8_t **outData, uint32_t *outLen)
{
    if (list == NULL || inData == NULL || inLen == 0 || outData == NULL || outLen == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t encDataLen = inLen + ENCRYPT_OVER_HEAD_LEN;
    uint8_t *encData = (uint8_t *)SoftBusCalloc(encDataLen);
    if (encData == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "malloc encrypt data fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (EncryptData(list, inData, inLen, encData, &encDataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "encrypt data fail.");
        SoftBusFree(encData);
        return SOFTBUS_ENCRYPT_ERR;
    }
    *outData = encData;
    *outLen = encDataLen;
    return SOFTBUS_OK;
}

int32_t DecryptInner(const SessionKeyList *list, const uint8_t *inData, uint32_t inLen,
    uint8_t **outData, uint32_t *outLen)
{
    if (list == NULL || inData == NULL || inLen <= ENCRYPT_OVER_HEAD_LEN || outData == NULL || outLen == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t decDataLen = inLen - ENCRYPT_OVER_HEAD_LEN + 1; /* for '\0' */
    uint8_t *decData = (uint8_t *)SoftBusCalloc(decDataLen);
    if (decData == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "malloc decrypt data fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (DecryptData(list, inData, inLen, decData, &decDataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "decrypt data fail.");
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
    CHECK_NULL_PTR_RETURN_VOID(list);
    uint32_t keyNum = 0;
    SessionKeyItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, (const ListNode *)list, SessionKeyItem, node) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_DBG,
            "[Dump] SessionKey[%d]: {index=%d, key: {len=%u, key=XX}, lastUseTime=%"PRIu64"}",
            keyNum, item->index, item->key.len, item->lastUseTime);
        keyNum++;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_DBG, "[Dump] SessionKey total num: %u", keyNum);
}

static void HandleUpdateSessionKeyEvent(const void *obj)
{
    CHECK_NULL_PTR_RETURN_VOID(obj);
    int64_t authId = *(int64_t *)(obj);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "update session key begin, authId=%" PRId64, authId);
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return;
    }
    if (AuthSessionStartAuth(GenSeq(false), AuthGenRequestId(),
        auth->connId, &auth->connInfo, false) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "start auth session to update session key fail, authId=%" PRId64, authId);
    }
    DelAuthManager(auth, false);
}

static int32_t RmoveUpdateSessionKeyFunc(const void *obj, void *para)
{
    CHECK_NULL_PTR_RETURN_VALUE(obj, SOFTBUS_ERR);
    CHECK_NULL_PTR_RETURN_VALUE(para, SOFTBUS_ERR);
    int64_t authId = *(int64_t *)(obj);
    if (authId == *(int64_t *)(para)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
            "remove update session key event, authId=%" PRId64, authId);
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

void ScheduleUpdateSessionKey(int64_t authId, uint64_t delayMs)
{
    RemoveAuthEvent(EVENT_UPDATE_SESSION_KEY, RmoveUpdateSessionKeyFunc, (void *)(&authId));
    PostAuthEvent(EVENT_UPDATE_SESSION_KEY, HandleUpdateSessionKeyEvent, &authId, sizeof(authId), delayMs);
}
