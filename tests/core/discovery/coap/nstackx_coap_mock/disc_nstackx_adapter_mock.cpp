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
#include "disc_nstackx_adapter_mock.h"
#include "softbus_error_code.h"

AdapterMock::AdapterMock()
{
    mock.store(this);
}

AdapterMock::~AdapterMock()
{
    mock.store(nullptr);
}

int32_t NSTACKX_Init(const NSTACKX_Parameter *parameter)
{
    return AdapterMock::ActionOfNstackInit(parameter);
}

int32_t NSTACKX_RegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    return SOFTBUS_OK;
}

int32_t NSTACKX_SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    return SOFTBUS_OK;
}

int32_t NSTACKX_SendDiscoveryRsp(const NSTACKX_ResponseSettings *responseSettings)
{
    return SOFTBUS_OK;
}

int32_t LnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    return AdapterMock::ActionOfLnnGetLocalStrInfoByIfnameIdx(key, info, len, ifIdx);
}

int32_t AdapterMock::ActionOfNstackInit(const NSTACKX_Parameter *parameter)
{
    deviceFoundCallback_ = *parameter;
    return SOFTBUS_OK;
}

int32_t AdapterMock::ActionOfLnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    
    (void)strncpy_s(info, len, "wlan0", strlen("wlan0"));
    return SOFTBUS_OK;
}

void AdapterMock::InjectDeviceFoundEvent(const NSTACKX_DeviceInfo *deviceInfo, uint32_t deviceCount)
{
    if (deviceFoundCallback_.onDeviceListChanged) {
        deviceFoundCallback_.onDeviceListChanged(deviceInfo, deviceCount);
    }
}
