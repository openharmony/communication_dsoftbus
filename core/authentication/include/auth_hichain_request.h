/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef AUTH_HICHAIN_REQUEST_H
#define AUTH_HICHAIN_REQUEST_H

#include <stdint.h>
#include <stdbool.h>
#include "auth_interface.h"
#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    int64_t authSeq;
    char udid[UDID_BUF_LEN];
    char peerUid[MAX_ACCOUNT_HASH_LEN];
    bool isServer;
    ListNode node;
} HichainRequest;

void NotifyHiChainRequestSuccess(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen);
void NotifyHiChainRequestFail(int64_t authSeq, bool isNeedReAuth);
uint32_t AddHichainRequest(const HichainRequest *request);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_HICHAIN_REQUEST_H */
