/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BR_PROXY_SERVER_MANAGER_H
#define BR_PROXY_SERVER_MANAGER_H

#include <stdbool.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t TransOpenBrProxy(const char *brMac, const char *uuid);
int32_t TransCloseBrProxy(int32_t channelId, bool isInnerCall);
int32_t TransSendBrProxyData(int32_t channelId, char* data, uint32_t dataLen);
int32_t TransSetListenerState(int32_t channelId, int32_t type, bool isEnable);
bool TransIsProxyChannelEnabled(int32_t uid);
int32_t TransRegisterPushHook();
void BrProxyClientDeathClearResource(pid_t callingPid);
bool IsBrProxy(const char *bundleName);
int32_t ApplyForUnrestricted(int32_t channelId);
void TransBrProxyRemoveObject(int32_t pid);
void UninstallHandler(const char *bundleName, int32_t appIndex, int32_t userId);

#ifdef __cplusplus
}
#endif

#endif