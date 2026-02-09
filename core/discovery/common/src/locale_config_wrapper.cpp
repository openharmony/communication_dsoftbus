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

#include <securec.h>
#include <string>

#include "disc_log.h"
#include "locale_config_wrapper.h"
#include "parameter.h"

#ifdef __cplusplus
extern "C" {
#endif

const std::string CHINESE_LANGUAGE = "zh-Hans";
const std::string TRADITIONAL_CHINESE_LANGUAGE = "zh-Hant";
static constexpr const char *LANGUAGE_KEY = "persist.global.language";
static constexpr const char *DEFAULT_LANGUAGE_KEY = "const.global.language";
static constexpr const int32_t CONFIG_LEN = 128;

static std::string ReadSystemParameter(const char *paramKey)
{
    char param[CONFIG_LEN + 1];
    (void)memset_s(param, CONFIG_LEN + 1, 0, CONFIG_LEN + 1);
    int32_t ret = GetParameter(paramKey, "", param, CONFIG_LEN);
    if (ret > 0) {
        return param;
    }
    DISC_LOGE(DISC_INIT, "GetParameter fail");
    return "";
}

bool IsZHLanguage(void)
{
    std::string systemLanguage = ReadSystemParameter(LANGUAGE_KEY);
    if (!systemLanguage.empty()) {
        return CHINESE_LANGUAGE == systemLanguage || TRADITIONAL_CHINESE_LANGUAGE == systemLanguage;
    }
    systemLanguage = ReadSystemParameter(DEFAULT_LANGUAGE_KEY);
    if (!systemLanguage.empty()) {
        return CHINESE_LANGUAGE == systemLanguage || TRADITIONAL_CHINESE_LANGUAGE == systemLanguage;
    }
    // Default language is Chinese.
    return true;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */