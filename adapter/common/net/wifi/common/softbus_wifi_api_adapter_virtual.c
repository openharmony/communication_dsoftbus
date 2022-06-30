/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <stdlib.h>
#include "securec.h"
#include "softbus_errcode.h"
#include "softbus_wifi_api_adapter.h"

int32_t SoftBusGetWifiDeviceConfig(SoftBusWifiDevConf *configList, uint32_t *num)
{
    (void)configList;
    (void)num;
    return SOFTBUS_OK;
}

int32_t SoftBusConnectToDevice(const SoftBusWifiDevConf *wifiConfig)
{
    (void)wifiConfig;
    return SOFTBUS_OK;
}

int32_t SoftBusDisconnectDevice(void)
{
    return SOFTBUS_OK;
}

int32_t SoftBusStartWifiScan(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SoftBusRegisterWifiEvent(ISoftBusScanResult *cb)
{
    (void)cb;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SoftBusGetWifiScanList(SoftBusWifiScanInfo **result, unsigned int *size)
{
    (void)result;
    (void)size;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SoftBusUnRegisterWifiEvent(ISoftBusScanResult *cb)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

