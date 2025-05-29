/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "nstackx_adapter_mock.h"
#include "softbus_error_code.h"
#include "disc_log.h"

const int32_t MOCK_PHONE_DEVICE_TYPE = 14;
const int32_t MOCK_ACCOUNT_ID = 1234567890;
const int32_t MOCK_AUTH_PORT = 1234;
const char *MOCK_DEVICE_ID = "ABCDEF11223344556677889900";
const char *MOCK_DEVICE_NAME = "deviceName";
const char *MOCK_WLAN_IP = "192.168.0.1";

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

int32_t NSTACKX_RegisterServiceDataV2(const struct NSTACKX_ServiceData *param, uint32_t cnt)
{
    return AdapterMock::ActionOfRegisterServiceDataV2(param, cnt);
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

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return AdapterMock::ActionOfLnnGetLocalNumInfo(key, info);
}

int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    return AdapterMock::ActionOfLnnGetLocalNum64Info(key, info);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return AdapterMock::ActionOfLnnGetLocalStrInfo(key, info, len);
}

int32_t LnnGetLocalNumInfoByIfnameIdx(InfoKey key, int32_t *info, int32_t ifIdx)
{
    return AdapterMock::ActionOfLnnGetLocalNumInfoByIfnameIdx(key, info, ifIdx);
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

int32_t AdapterMock::ActionOfRegisterServiceDataV2(const struct NSTACKX_ServiceData *param, uint32_t cnt)
{
    if (cnt == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

int32_t AdapterMock::ActionOfLnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (key == NUM_KEY_DEV_TYPE_ID) {
        *info = MOCK_PHONE_DEVICE_TYPE;
    }
    return SOFTBUS_OK;
}

int32_t AdapterMock::ActionOfLnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (key == NUM_KEY_ACCOUNT_LONG) {
        *info = MOCK_ACCOUNT_ID;
    }
    return SOFTBUS_OK;
}

int32_t AdapterMock::ActionOfLnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (key == STRING_KEY_DEV_UDID) {
        (void)strncpy_s(info, len, MOCK_DEVICE_ID, strlen(MOCK_DEVICE_ID));
    }
    if (key == STRING_KEY_DEV_NAME) {
        (void)strncpy_s(info, len, MOCK_DEVICE_NAME, strlen(MOCK_DEVICE_NAME));
    }
    return SOFTBUS_OK;
}

int32_t AdapterMock::ActionOfLnnGetLocalNumInfoByIfnameIdx(InfoKey key, int32_t *info, int32_t ifIdx)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (key == NUM_KEY_AUTH_PORT) {
        *info = MOCK_AUTH_PORT;
    }
    return SOFTBUS_OK;
}

int32_t AdapterMock::ActionOfLnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (key == STRING_KEY_IP) {
        (void)strncpy_s(info, len, MOCK_WLAN_IP, strlen(MOCK_WLAN_IP));
    }
    if (key == STRING_KEY_NET_IF_NAME) {
        (void)strncpy_s(info, len, "wlan0", strlen("wlan0"));
    }
    return SOFTBUS_OK;
}

void AdapterMock::InjectDeviceFoundEvent(const NSTACKX_DeviceInfo *deviceInfo, uint32_t deviceCount)
{
    if (deviceFoundCallback_.onDeviceListChanged) {
        deviceFoundCallback_.onDeviceListChanged(deviceInfo, deviceCount);
    }
}

void AdapterMock::SetupSuccessStub()
{
    EXPECT_CALL(*this, NSTACKX_RegisterServiceDataV2).WillRepeatedly(AdapterMock::ActionOfRegisterServiceDataV2);
    EXPECT_CALL(*this, LnnGetLocalNumInfo).WillRepeatedly(AdapterMock::ActionOfLnnGetLocalNumInfo);
    EXPECT_CALL(*this, LnnGetLocalNum64Info).WillRepeatedly(AdapterMock::ActionOfLnnGetLocalNum64Info);
    EXPECT_CALL(*this, LnnGetLocalStrInfo).WillRepeatedly(AdapterMock::ActionOfLnnGetLocalStrInfo);
    EXPECT_CALL(*this, LnnGetLocalNumInfoByIfnameIdx).
        WillRepeatedly(AdapterMock::ActionOfLnnGetLocalNumInfoByIfnameIdx);
    EXPECT_CALL(*this, LnnGetLocalStrInfoByIfnameIdx).
        WillRepeatedly(AdapterMock::ActionOfLnnGetLocalStrInfoByIfnameIdx);
}