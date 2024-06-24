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

#ifndef AUTH_NORMALIZE_REQUEST_H
#define AUTH_NORMALIZE_REQUEST_H

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
    char udidHash[SHA_256_HEX_HASH_LEN];
    int64_t authSeq;
    AuthConnInfo connInfo;
    bool isConnectServer;
    ListNode node;
} NormalizeRequest;

bool AuthIsRepeatedAuthRequest(int64_t authSeq);
uint32_t AddNormalizeRequest(const NormalizeRequest *request);
void NotifyNormalizeRequestSuccess(int64_t authSeq, bool isSupportNego);
void NotifyNormalizeRequestFail(int64_t authSeq, int32_t ret);
void DelAuthNormalizeRequest(int64_t authSeq);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_NORMALIZE_REQUEST_H */
