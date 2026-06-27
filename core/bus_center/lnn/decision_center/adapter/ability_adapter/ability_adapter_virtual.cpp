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

#include "ability_adapter.h"

#include "softbus_error_code.h"

constexpr int32_t ERR_OK = 0;
#define GET_EXTENSION_UPPER_LIMIT 100

int32_t StartAbility(const char *bundleName, const char *abilityName)
{
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

bool IsRunningProcess(const char *bundleName, int32_t userId)
{
    return false;
}

bool IsExtensionAbility(const char *bundleName, const char *abilityName, int32_t upperLimit)
{
    return false;
}