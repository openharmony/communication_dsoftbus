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

#include "locale_config.h"
#include "locale_config_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

const std::string CHINESE_LANGUAGE = "zh-Hans";
const std::string TRADITIONAL_CHINESE_LANGUAGE = "zh-Hant";

bool IsZHLanguage(void)
{
    auto language = OHOS::Global::I18n::LocaleConfig::GetSystemLanguage();
    return CHINESE_LANGUAGE == language || TRADITIONAL_CHINESE_LANGUAGE == language;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */