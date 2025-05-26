/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_settingdata_event_monitor.h"

#include <securec.h>
#include <string>

#include "anonymizer.h"
#include "lnn_log.h"
#include "parameter.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

const std::string CHINESE_LANGUAGE = "zh-Hans";
const std::string TRADITIONAL_CHINESE_LANGUAGE = "zh-Hant";
static constexpr const char *LANGUAGE_KEY = "persist.global.language";
static constexpr const char *DEFAULT_LANGUAGE_KEY = "const.global.language";
static constexpr const char *INTERNAL_NAME_CONCAT_STRING = "的";
static constexpr const char *EXTERNAL_NAME_CONCAT_STRING = "-";
static constexpr const int32_t CONFIG_LEN = 128;

static std::string ReadSystemParameter(const char *paramKey)
{
    char param[CONFIG_LEN + 1];
    (void)memset_s(param, CONFIG_LEN + 1, 0, CONFIG_LEN + 1);
    int32_t ret = GetParameter(paramKey, "", param, CONFIG_LEN);
    if (ret > 0) {
        return param;
    }
    LNN_LOGE(LNN_STATE, "GetParameter failed");
    return "";
}

int32_t LnnGetUnifiedDeviceName(char *unifiedName, uint32_t len)
{
    (void)unifiedName;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetUnifiedDefaultDeviceName(char *unifiedDefaultName, uint32_t len)
{
    (void)unifiedDefaultName;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetSettingNickName(const char *defaultName, const char *unifiedName, char *nickName, uint32_t len)
{
    (void)defaultName;
    (void)unifiedName;
    (void)nickName;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

static bool IsZHLanguage(void)
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

int32_t LnnGetDeviceDisplayName(const char *nickName, const char *defaultName, char *deviceName, uint32_t len)
{
    if (nickName == nullptr || defaultName == nullptr || deviceName == nullptr) {
        LNN_LOGE(LNN_STATE, "param is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    char devName[DEVICE_NAME_BUF_LEN] = {0};
    if (IsZHLanguage()) {
        if (sprintf_s(devName, DEVICE_NAME_BUF_LEN, "%s%s%s", nickName,
            INTERNAL_NAME_CONCAT_STRING, defaultName) < 0) {
            LNN_LOGE(LNN_STATE, "sprintf_s devName fail.");
            return SOFTBUS_SPRINTF_ERR;
        }
    } else {
        if (sprintf_s(devName, DEVICE_NAME_BUF_LEN, "%s%s%s", nickName,
            EXTERNAL_NAME_CONCAT_STRING, defaultName) < 0) {
            LNN_LOGE(LNN_STATE, "sprintf_s devName fail.");
            return SOFTBUS_SPRINTF_ERR;
        }
    }
    if (strcpy_s(deviceName, len, devName) != EOK) {
        LNN_LOGE(LNN_STATE, "strcpy_s devName fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    char *anonyDeviceName = NULL;
    Anonymize(deviceName, &anonyDeviceName);
    LNN_LOGD(LNN_STATE, "deviceName=%{public}s.", AnonymizeWrapper(anonyDeviceName));
    AnonymizeFree(anonyDeviceName);
    return SOFTBUS_OK;
}
