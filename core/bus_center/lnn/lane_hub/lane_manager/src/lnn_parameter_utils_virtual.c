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

#include "lnn_parameter_utils.h"

bool IsCloudSyncEnabled(void)
{
    return false;
}

bool IsPowerControlEnabled(void)
{
    return false;
}

int32_t SetWifiConfigRemoteBaseMac(uint8_t *mac, uint8_t *wifiConfig, int32_t *cfgLen)
{
    (void)mac;
    (void)wifiConfig;
    (void)cfgLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetWifiConfigBaseMac(char *mac)
{
    (void)mac;
    return SOFTBUS_NOT_IMPLEMENT;
}