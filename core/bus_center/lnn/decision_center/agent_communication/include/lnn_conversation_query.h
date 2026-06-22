/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef LNN_CONVERSATION_QUERY_H
#define LNN_CONVERSATION_QUERY_H

#include <stdint.h>

#include "softbus_agent_communication.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnGetTrustedDevices(DeviceNodeInfo **info, int32_t *nums);
int32_t LnnRegisterConversationListener(const ConversationBusiness *info);
void LnnUnregisterConversationListener(const ConversationBusiness *info);
void OnRecvCloudQueryInfo(const char *udid, const char *data, uint32_t length);
int32_t LnnPostConversationData(const char *deviceId, const ConversationBusiness *info,
    const char *data, uint32_t len);
int32_t InitConversationQuery(void);
void DeinitConversationQuery(void);
int32_t DestroyNearFieldChannel(const char *udid);

#ifdef __cplusplus
}
#endif
#endif /* LNN_CONVERSATION_QUERY_H */