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

#ifndef AUTH_SESSIONKEY_H
#define AUTH_SESSIONKEY_H

#include "auth_manager.h"
#include "common_list.h"
#include "softbus_crypto.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESSAGE_INDEX_LEN 4
#define ENCRYPT_OVER_HEAD_LEN (OVERHEAD_LEN + MESSAGE_INDEX_LEN)
#define MAX_KEY_LIST_SIZE 10
#define LOW_32_BIT 0xFFFFFFFF

typedef struct {
    uint32_t type;
    char deviceKey[MAX_DEVICE_KEY_LEN];
    uint32_t deviceKeyLen;
    AuthSideFlag side;
    int32_t seq;
} NecessaryDevInfo;

typedef struct {
    char deviceKey[MAX_DEVICE_KEY_LEN];
    uint32_t deviceKeyLen;
    uint32_t type;
    int32_t seq;
    uint8_t sessionKey[SESSION_KEY_LENGTH];
    uint32_t sessionKeyLen;
    char peerUdid[UDID_BUF_LEN];
    AuthSideFlag side;
    ListNode node;
} SessionKeyList;

void AuthSetLocalSessionKey(const NecessaryDevInfo *devInfo, const char *peerUdid,
    const uint8_t *sessionKey, uint32_t sessionKeyLen);
bool AuthIsDeviceVerified(uint32_t type, const char *deviceKey, uint32_t deviceKeyLen);
bool AuthIsSeqInKeyList(int32_t seq);
void AuthSessionKeyListInit(void);
void AuthClearSessionKeyByDeviceInfo(uint32_t type, const char *deviceKey, uint32_t deviceKeyLen);
void AuthClearAllSessionKey(void);

#ifdef __cplusplus
}
#endif
#endif /* AUTH_SESSIONKEY_H */
