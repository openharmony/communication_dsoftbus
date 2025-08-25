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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t PullUpHap(const char *bundleName, const char *abilityName);
int32_t GetCallerHapInfo(char *bundleName, uint32_t bundleNamelen, char *abilityName, uint32_t abilityNameLen);
pid_t GetCallerPid();
pid_t GetCallerUid();
uint32_t GetCallerTokenId();
int32_t CheckPushPermission();

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // BR_PROXY_H