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
#include <securec.h>
#include "disc_coap_mock.h"
#include "softbus_error_code.h"

const int32_t MOCK_PHONE_DEVICE_TYPE = 14;
const int32_t MOCK_ACCOUNT_ID = 1234567890;
const int32_t MOCK_AUTH_PORT = 1234;
const char *MOCK_DEVICE_ID = "ABCDEF11223344556677889900";
const char *MOCK_DEVICE_NAME = "deviceName";
const char *MOCK_WLAN_IP = "192.168.0.1";

DiscCoapMock::DiscCoapMock()
{
    mock.store(this);
}

DiscCoapMock::~DiscCoapMock()
{
    mock.store(nullptr);
}

int32_t NSTACKX_RegisterServiceDataV2(const struct NSTACKX_ServiceData *param, uint32_t cnt)
{
    return DiscCoapMock::GetMock()->NSTACKX_RegisterServiceDataV2(param, cnt);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return DiscCoapMock::GetMock()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    return DiscCoapMock::GetMock()->LnnGetLocalNum64Info(key, info);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return DiscCoapMock::GetMock()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnGetLocalNumInfoByIfnameIdx(InfoKey key, int32_t *info, int32_t ifIdx)
{
    return DiscCoapMock::GetMock()->LnnGetLocalNumInfoByIfnameIdx(key, info, ifIdx);
}

int32_t LnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    return DiscCoapMock::GetMock()->LnnGetLocalStrInfoByIfnameIdx(key, info, len, ifIdx);
}

int32_t DiscCoapMock::ActionOfRegisterServiceDataV2(const struct NSTACKX_ServiceData *param, uint32_t cnt)
{
    if (cnt == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapMock::ActionOfLnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (key == NUM_KEY_DEV_TYPE_ID) {
        *info = MOCK_PHONE_DEVICE_TYPE;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapMock::ActionOfLnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (key == NUM_KEY_ACCOUNT_LONG) {
        *info = MOCK_ACCOUNT_ID;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapMock::ActionOfLnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
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

int32_t DiscCoapMock::ActionOfLnnGetLocalNumInfoByIfnameIdx(InfoKey key, int32_t *info, int32_t ifIdx)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (key == NUM_KEY_AUTH_PORT) {
        *info = MOCK_AUTH_PORT;
    }
    return SOFTBUS_OK;
}

int32_t DiscCoapMock::ActionOfLnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx)
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

void DiscCoapMock::SetupSuccessStub()
{
    EXPECT_CALL(*this, NSTACKX_RegisterServiceDataV2).WillRepeatedly(DiscCoapMock::ActionOfRegisterServiceDataV2);
    EXPECT_CALL(*this, LnnGetLocalNumInfo).WillRepeatedly(DiscCoapMock::ActionOfLnnGetLocalNumInfo);
    EXPECT_CALL(*this, LnnGetLocalNum64Info).WillRepeatedly(DiscCoapMock::ActionOfLnnGetLocalNum64Info);
    EXPECT_CALL(*this, LnnGetLocalStrInfo).WillRepeatedly(DiscCoapMock::ActionOfLnnGetLocalStrInfo);
    EXPECT_CALL(*this, LnnGetLocalNumInfoByIfnameIdx).
        WillRepeatedly(DiscCoapMock::ActionOfLnnGetLocalNumInfoByIfnameIdx);
    EXPECT_CALL(*this, LnnGetLocalStrInfoByIfnameIdx).
        WillRepeatedly(DiscCoapMock::ActionOfLnnGetLocalStrInfoByIfnameIdx);
}