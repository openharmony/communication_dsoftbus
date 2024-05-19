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

#ifndef AUTH_SESSION_KEY_H
#define AUTH_SESSION_KEY_H

#include <stdint.h>
#include <stdbool.h>

#include "auth_interface.h"
#include "common_list.h"
#include "softbus_adapter_crypto.h"
#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define ENCRYPT_INDEX_LEN 4
#define ENCRYPT_OVER_HEAD_LEN (OVERHEAD_LEN + ENCRYPT_INDEX_LEN)

typedef struct {
    uint8_t value[SESSION_KEY_LENGTH];
    uint32_t len;
} SessionKey;

typedef struct {
    const uint8_t *inData;
    uint32_t inLen;
} InDataInfo;
typedef ListNode SessionKeyList;

void InitSessionKeyList(SessionKeyList *list);
void DestroySessionKeyList(SessionKeyList *list);
int32_t DupSessionKeyList(const SessionKeyList *srcList, SessionKeyList *dstList);

uint64_t GetLatestAvailableSessionKeyTime(const SessionKeyList *list, AuthLinkType type);
bool HasSessionKey(const SessionKeyList *list);
AuthLinkType GetSessionKeyTypeByIndex(const SessionKeyList *list, int32_t index);
int32_t AddSessionKey(SessionKeyList *list, int32_t index, const SessionKey *key, AuthLinkType type,
    bool isOldKey);
int32_t SetSessionKeyAvailable(SessionKeyList *list, int32_t index);
int32_t GetLatestSessionKey(const SessionKeyList *list, AuthLinkType type, int32_t *index, SessionKey *key);
int32_t GetSessionKeyByIndex(const SessionKeyList *list, int32_t index, AuthLinkType type, SessionKey *key);
int32_t SetSessionKeyAuthLinkType(const SessionKeyList *list, int32_t index, AuthLinkType type);
bool CheckSessionKeyListExistType(const SessionKeyList *list, AuthLinkType type);
bool CheckSessionKeyListHasOldKey(const SessionKeyList *list, AuthLinkType type);
int32_t ClearOldKey(const SessionKeyList *list, AuthLinkType type);
void RemoveSessionkeyByIndex(SessionKeyList *list, int32_t index, AuthLinkType type);
void ClearSessionkeyByAuthLinkType(int64_t authId, SessionKeyList *list, AuthLinkType type);

int32_t EncryptInner(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
    uint8_t **outData, uint32_t *outLen);
int32_t DecryptInner(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
    uint8_t **outData, uint32_t *outLen);

int32_t EncryptData(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
    uint8_t *outData, uint32_t *outLen);
int32_t DecryptData(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
    uint8_t *outData, uint32_t *outLen);

void ScheduleUpdateSessionKey(AuthHandle authHandle, uint64_t delatMs);
void CancelUpdateSessionKey(int64_t authId);

/* For Debug */
void DumpSessionkeyList(const SessionKeyList *list);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_SESSION_KEY_H */
