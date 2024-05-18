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

#ifndef TRANS_AUTH_NEGOTIATION_H
#define TRANS_AUTH_NEGOTIATION_H

#include <stdint.h>

#include "auth_interface.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t TransNegotiateSessionKey(const AuthConnInfo *authConnInfo, int32_t channelId, const char *peerNetworkId);
int32_t TransReNegotiateSessionKey(const AuthConnInfo *authConnInfo, int32_t channelId);

int32_t TransReqAuthPendingInit(void);
void TransReqAuthPendingDeinit(void);

int32_t GetAuthConnInfoByConnId(uint32_t connectionId, AuthConnInfo *authConnInfo);

void TransAuthNegoTaskManager(uint32_t authRequestId, int32_t channelId);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
