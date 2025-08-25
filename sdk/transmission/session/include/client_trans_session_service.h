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

#ifndef CLIENT_TRANS_SESSION_SERVICE_H
#define CLIENT_TRANS_SESSION_SERVICE_H

#include "session.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t QosReport(int32_t sessionId, int32_t appType, int32_t quality);
int OpenSessionSync(const char *mySessionName, const char *peerSessionName, const char *peerNetworkId,
    const char *groupId, const SessionAttribute *attr);
int32_t GetDefaultConfigType(int32_t channelType, int32_t businessType);
bool RemoveAppIdFromSessionName(const char *sessionName, char *newSessionName, int32_t length);
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_SESSION_SERVICE_H
