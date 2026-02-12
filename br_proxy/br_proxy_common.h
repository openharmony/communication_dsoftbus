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
#ifndef BR_PROXY_COMMON_HANDLE_H
#define BR_PROXY_COMMON_HANDLE_H

#include "br_proxy.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#define HAP_NAME_MAX_LEN            256

typedef enum {
    LOOP_DCLOSE_MSG,
    LOOP_STOP_APP_MSG,
    LOOP_BR_PROXY_OPENED_MSG,
} BrProxyLoopMsg;

typedef struct {
    char bundleName[HAP_NAME_MAX_LEN];
    pid_t pid;
    pid_t uid;
} StopAppInfo;

typedef struct {
    pid_t pid;
    int32_t channelId;
    char brMac[BR_MAC_LEN];
    char uuid[UUID_LEN];
} BrProxyOpenedInfo;

int32_t PullUpHap(const char *bundleName, const char *abilityName, int32_t appIndex);
int32_t GetCallerHapInfo(char *bundleName, uint32_t bundleNamelen,
    char *abilityName, uint32_t abilityNameLen, int32_t *appIndex);
pid_t GetCallerPid();
pid_t GetCallerUid();
uint32_t GetCallerTokenId();
int32_t CheckPushPermission();
void BrProxyPostDcloseMsgToLooperDelay(uint32_t delayTime);
int32_t DynamicLoadInit();
int32_t BrProxyUnrestricted(const char *bundleName, pid_t pid, pid_t uid, bool isThaw);
int32_t BrProxyPostMsgToLooper(int32_t what, uint64_t arg1, uint64_t arg2, void *obj, uint64_t delayMillis);
void BrProxyRemoveMsgFromLooper(int32_t what, uint64_t arg1, uint64_t arg2, void *obj);
int32_t BrProxyLoopInit(void);
bool CommonGetRunningProcessInformation(const char *bundleName, int32_t userId, pid_t uid, pid_t *pid);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // BR_PROXY_COMMON_H