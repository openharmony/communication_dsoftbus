/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "softbus_error_code.h"

int32_t LnnGetUnifiedDisplayDeviceName(char *unifiedDisplayName, uint32_t len)
{
    (void)unifiedDisplayName;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
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

int32_t LnnGetDeviceDisplayName(const char *nickName, const char *defaultName, char *deviceName, uint32_t len)
{
    (void)nickName;
    (void)defaultName;
    (void)deviceName;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}
