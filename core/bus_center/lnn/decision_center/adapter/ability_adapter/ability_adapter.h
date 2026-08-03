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

#ifndef ABILITY_ADAPTER_H
#define ABILITY_ADAPTER_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

int32_t StartAbility(const char *bundleName, const char *abilityName, int32_t userId);

bool IsRunningProcess(const char *bundleName, int32_t userId);

bool IsExtensionAbility(const char *bundleName, const char *abilityName, int32_t upperLimit);

#ifdef __cplusplus
}
#endif

#endif // ABILITY_ADAPTER_H