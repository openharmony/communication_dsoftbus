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
#ifndef SOFTBUS_SESSION_LISTENER
#define SOFTBUS_SESSION_LISTENER

#include "softbus_base_listener.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    ListNode node;
    char myIp[IP_LEN];
    int32_t myPort;
    ListenerModule moudleType;
} HmlListenerInfo;

int32_t GetCipherFlagByAuthId(int64_t authId, uint32_t *flag, bool *isAuthServer);

int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info);

int32_t TransTdcStopSessionListener(ListenerModule module);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
