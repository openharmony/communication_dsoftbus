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

#include "anonymizer.h"
#include "lnn_log.h"
#include "locale_config.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

static constexpr const char *INTERNAL_NAME_CONCAT_STRING = "的";
static constexpr const char *EXTERNAL_NAME_CONCAT_STRING = "-";

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
    std::string language = OHOS::Global::I18n::LocaleConfig::GetSystemLanguage();
    return "zh-Hans" == language || "zh-Hant" == language;
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
