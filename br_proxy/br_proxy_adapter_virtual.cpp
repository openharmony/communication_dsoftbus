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

#include "softbus_error_code.h"

using namespace OHOS;

extern "C" int32_t StartAbility(const char *bundleName, const char *abilityName)
{
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

extern "C" int32_t ProxyChannelMgrGetAbilityName(char *abilityName, int32_t userId,
    uint32_t abilityNameLen, std::string bundleName)
{
    return SOFTBUS_FUNC_NOT_SUPPORT;
}