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

#ifndef AUTH_REQUEST_H
#define AUTH_REQUEST_H

#include <stdint.h>
#include <stdbool.h>
#include "auth_interface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    REQUEST_TYPE_VERIFY = 0,
    REQUEST_TYPE_RECONNECT,
    REQUEST_TYPE_CONNECT,
} RequestType;

typedef struct {
    uint32_t requestId;
    AuthConnInfo connInfo;
    AuthVerifyCallback verifyCb;
    AuthVerifyModule module;
    int64_t authId;
    int64_t traceId;
    AuthConnCallback connCb;
    RequestType type;
    ListNode node;
    uint64_t addTime;
    bool isFastAuth;
} AuthRequest;

bool CheckVerifyCallback(const AuthVerifyCallback *verifyCb);
bool CheckAuthConnCallback(const AuthConnCallback *connCb);

/* Note: return wait list num, 0 means add fail. */
uint32_t AddAuthRequest(const AuthRequest *request);
int32_t GetAuthRequest(uint32_t requestId, AuthRequest *request);
int32_t FindAuthRequestByConnInfo(const AuthConnInfo *connInfo, AuthRequest *request);
int32_t GetAuthRequestNoLock(uint32_t requestId, AuthRequest *request);
int32_t FindAndDelAuthRequestByConnInfo(uint32_t requestId, const AuthConnInfo *connInfo);
void DelAuthRequest(uint32_t requestId);
void ClearAuthRequest(void);

void PerformVerifyCallback(uint32_t requestId, int32_t result, AuthHandle authHandle, const NodeInfo *info);
void PerformAuthConnCallback(uint32_t requestId, int32_t result, int64_t authId);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_REQUEST_H */
