/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "auth_sessionkey.h"

#include <securec.h>

#include "auth_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#ifdef __cplusplus
extern "C" {
#endif

static ListNode g_sessionKeyListHead;

void AuthSessionKeyListInit(void)
{
    ListInit(&g_sessionKeyListHead);
}

void AuthSetLocalSessionKey(const NecessaryDevInfo *devInfo, const char *peerUdid,
    const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    uint32_t listSize = 0;
    if (devInfo == NULL || peerUdid == NULL || sessionKey == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return;
    }
    SessionKeyList *sessionKeyList = NULL;
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_sessionKeyListHead) {
        listSize++;
    }
    if (listSize == MAX_KEY_LIST_SIZE) {
        item = GET_LIST_TAIL(&g_sessionKeyListHead);
        sessionKeyList = LIST_ENTRY(item, SessionKeyList, node);
        (void)memset_s(sessionKeyList->sessionKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
        ListDelete(&sessionKeyList->node);
        SoftBusFree(sessionKeyList);
        sessionKeyList = NULL;
    }
    sessionKeyList = (SessionKeyList *)SoftBusMalloc(sizeof(SessionKeyList));
    if (sessionKeyList == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
        return;
    }
    (void)memset_s(sessionKeyList, sizeof(SessionKeyList), 0, sizeof(SessionKeyList));
    sessionKeyList->type = devInfo->type;
    sessionKeyList->side = devInfo->side;
    sessionKeyList->seq = devInfo->seq;
    if (memcpy_s(sessionKeyList->peerUdid, UDID_BUF_LEN, peerUdid, strlen(peerUdid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
        SoftBusFree(sessionKeyList);
        return;
    }
    if (memcpy_s(sessionKeyList->deviceKey, MAX_DEVICE_KEY_LEN, devInfo->deviceKey, devInfo->deviceKeyLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
        SoftBusFree(sessionKeyList);
        return;
    }
    sessionKeyList->deviceKeyLen = devInfo->deviceKeyLen;
    if (memcpy_s(sessionKeyList->sessionKey, SESSION_KEY_LENGTH, sessionKey, sessionKeyLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
        SoftBusFree(sessionKeyList);
        return;
    }
    sessionKeyList->sessionKeyLen = sessionKeyLen;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth add sessionkey, seq is:%d", sessionKeyList->seq);
    ListNodeInsert(&g_sessionKeyListHead, &sessionKeyList->node);
}

bool AuthIsDeviceVerified(uint32_t type, const char *deviceKey, uint32_t deviceKeyLen)
{
    if (deviceKey == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return false;
    }
    SessionKeyList *sessionKeyList = NULL;
    if (IsListEmpty(&g_sessionKeyListHead) == true) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "no session key in memory, need to verify device");
        return false;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_sessionKeyListHead) {
        sessionKeyList = LIST_ENTRY(item, SessionKeyList, node);
        if (sessionKeyList->type == type && strncmp(sessionKeyList->deviceKey, deviceKey, deviceKeyLen) == 0) {
            return true;
        }
    }
    return false;
}

bool AuthIsSeqInKeyList(int32_t seq)
{
    SessionKeyList *sessionKeyList = NULL;
    if (IsListEmpty(&g_sessionKeyListHead) == true) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "no session key in memory");
        return false;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_sessionKeyListHead) {
        sessionKeyList = LIST_ENTRY(item, SessionKeyList, node);
        if (sessionKeyList->seq == seq) {
            return true;
        }
    }
    return false;
}

static SessionKeyList *AuthGetLastSessionKey(const NecessaryDevInfo *devInfo)
{
    if (devInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return NULL;
    }
    SessionKeyList *sessionKeyList = NULL;
    if (IsListEmpty(&g_sessionKeyListHead) == true) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no session key in memory");
        return NULL;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_sessionKeyListHead) {
        sessionKeyList = LIST_ENTRY(item, SessionKeyList, node);
        if (sessionKeyList->type == devInfo->type &&
            strncmp(sessionKeyList->deviceKey, devInfo->deviceKey, devInfo->deviceKeyLen) == 0) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
                "auth get last session key succ, seq is:%d", sessionKeyList->seq);
            return sessionKeyList;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get last session key failed");
    return NULL;
}

static SessionKeyList *GetSessionKeyByDevinfo(const NecessaryDevInfo *devInfo)
{
    if (devInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return NULL;
    }
    SessionKeyList *sessionKeyList = NULL;
    if (IsListEmpty(&g_sessionKeyListHead) == true) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no session key in memory");
        return NULL;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_sessionKeyListHead) {
        sessionKeyList = LIST_ENTRY(item, SessionKeyList, node);
        if (sessionKeyList->type == devInfo->type &&
            sessionKeyList->seq == devInfo->seq &&
            strncmp(sessionKeyList->deviceKey, devInfo->deviceKey, devInfo->deviceKeyLen) == 0) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
                "auth get session key by dev info succ, seq is:%d", sessionKeyList->seq);
            return sessionKeyList;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth cannot find session key by dev info");
    return NULL;
}

static SessionKeyList *AuthGetSessionKeyBySeq(int32_t seq)
{
    SessionKeyList *sessionKeyList = NULL;
    if (IsListEmpty(&g_sessionKeyListHead) == true) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no session key in memory");
        return NULL;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth get session key by seq %d", seq);
    ListNode *item = NULL;
    ListNode *tmp = NULL;
    LIST_FOR_EACH_SAFE(item, tmp, &g_sessionKeyListHead) {
        sessionKeyList = LIST_ENTRY(item, SessionKeyList, node);
        if (sessionKeyList->seq == seq) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth get session key by seq seccessfully.");
            return sessionKeyList;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get session key by seq failed");
    return NULL;
}

int32_t AuthEncryptBySeq(int32_t seq, AuthSideFlag *side, uint8_t *data, uint32_t len, OutBuf *outBuf)
{
    if (data == NULL || outBuf == NULL || outBuf->bufLen < (len + ENCRYPT_OVER_HEAD_LEN)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    SessionKeyList *sessionKeyList = NULL;
    uint32_t outLen;

    sessionKeyList = AuthGetSessionKeyBySeq(seq);
    if (sessionKeyList == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthGetLastSessionKey failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    *side = sessionKeyList->side;
    // add seq first
    if (memcpy_s(outBuf->buf, sizeof(int32_t), &sessionKeyList->seq, sizeof(int32_t)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    AesGcmCipherKey cipherKey = {0};
    cipherKey.keyLen = sessionKeyList->sessionKeyLen;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKeyList->sessionKey, sessionKeyList->sessionKeyLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (SoftBusEncryptDataWithSeq(&cipherKey, data, len, outBuf->buf + MESSAGE_INDEX_LEN,
        &outLen, sessionKeyList->seq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusEncryptDataWithSeq failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    outBuf->outLen = outLen + MESSAGE_INDEX_LEN;
    return SOFTBUS_OK;
}

int32_t AuthEncrypt(const ConnectOption *option, AuthSideFlag *side, uint8_t *data, uint32_t len, OutBuf *outBuf)
{
    if (option == NULL || side == NULL || data == NULL ||
        outBuf == NULL || outBuf->bufLen < (len + ENCRYPT_OVER_HEAD_LEN)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret;
    SessionKeyList *sessionKeyList = NULL;
    NecessaryDevInfo devInfo = {0};
    uint32_t outLen;

    devInfo.type = option->type;
    ret = AuthGetDeviceKey(devInfo.deviceKey, MAX_DEVICE_KEY_LEN, &(devInfo.deviceKeyLen), option);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthGetDeviceKey failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    sessionKeyList = AuthGetLastSessionKey(&devInfo);
    if (sessionKeyList == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthGetLastSessionKey failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    *side = sessionKeyList->side;
    // add seq first
    if (memcpy_s(outBuf->buf, sizeof(int32_t), &sessionKeyList->seq, sizeof(int32_t)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    AesGcmCipherKey cipherKey = {0};
    cipherKey.keyLen = sessionKeyList->sessionKeyLen;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKeyList->sessionKey, sessionKeyList->sessionKeyLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (SoftBusEncryptDataWithSeq(&cipherKey, data, len, outBuf->buf + MESSAGE_INDEX_LEN,
        &outLen, sessionKeyList->seq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusEncryptDataWithSeq failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    outBuf->outLen = outLen + MESSAGE_INDEX_LEN;
    return SOFTBUS_OK;
}

int32_t AuthDecrypt(const ConnectOption *option, AuthSideFlag side, uint8_t *data, uint32_t len, OutBuf *outBuf)
{
    if (option == NULL || data == NULL || outBuf == NULL || outBuf->bufLen < (len - ENCRYPT_OVER_HEAD_LEN)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    SessionKeyList *sessionKeyList = NULL;
    NecessaryDevInfo devInfo = {0};
    devInfo.type = option->type;

    int32_t ret = AuthGetDeviceKey(devInfo.deviceKey, MAX_DEVICE_KEY_LEN, &(devInfo.deviceKeyLen), option);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthGetDeviceKey failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    int32_t seq;
    if (memcpy_s(&seq, sizeof(int32_t), data, sizeof(int32_t)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    devInfo.seq = seq;
    data += sizeof(int32_t);
    len -= sizeof(int32_t);
    devInfo.side = side;
    sessionKeyList = GetSessionKeyByDevinfo(&devInfo);
    if (sessionKeyList == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "GetSessionKeyByDevinfo failed");
        return SOFTBUS_ENCRYPT_ERR;
    }

    AesGcmCipherKey cipherKey = {0};
    cipherKey.keyLen = sessionKeyList->sessionKeyLen;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKeyList->sessionKey, sessionKeyList->sessionKeyLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (SoftBusDecryptDataWithSeq(&cipherKey, data, len, outBuf->buf,
        &outBuf->outLen, sessionKeyList->seq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusDecryptDataWithSeq failed");
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

uint32_t AuthGetEncryptHeadLen(void)
{
    return ENCRYPT_OVER_HEAD_LEN;
}

void AuthClearSessionKeyBySeq(int32_t seq)
{
    SessionKeyList *sessionKeyList = NULL;
    if (IsListEmpty(&g_sessionKeyListHead) == true) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no session key in memory");
        return;
    }
    ListNode *item = NULL;
    ListNode *tmp = NULL;
    LIST_FOR_EACH_SAFE(item, tmp, &g_sessionKeyListHead) {
        sessionKeyList = LIST_ENTRY(item, SessionKeyList, node);
        if (sessionKeyList->seq == seq) {
            (void)memset_s(sessionKeyList->sessionKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
            ListDelete(&sessionKeyList->node);
            SoftBusFree(sessionKeyList);
            sessionKeyList = NULL;
        }
    }
}

void AuthClearAllSessionKey(void)
{
    SessionKeyList *sessionKeyList = NULL;
    if (IsListEmpty(&g_sessionKeyListHead) == true) {
        return;
    }
    ListNode *item = NULL;
    ListNode *tmp = NULL;
    LIST_FOR_EACH_SAFE(item, tmp, &g_sessionKeyListHead) {
        sessionKeyList = LIST_ENTRY(item, SessionKeyList, node);
        (void)memset_s(sessionKeyList->sessionKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
        ListDelete(&sessionKeyList->node);
        SoftBusFree(sessionKeyList);
        sessionKeyList = NULL;
    }
    ListInit(&g_sessionKeyListHead);
}

#ifdef __cplusplus
}
#endif
