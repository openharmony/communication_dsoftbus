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
#include "nstackx_adapter_mock.h"
#include "softbus_error_code.h"

AdapterMock::AdapterMock()
{
    mock.store(this);
}

AdapterMock::~AdapterMock()
{
    mock.store(nullptr);
}

int32_t NSTACKX_RegisterServiceDataV2(const struct NSTACKX_ServiceData *param, uint32_t cnt)
{
    return AdapterMock::ActionRegisterServiceDataV2(param, cnt);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return AdapterMock::ActionLnnGetLocalNumInfo(key, info);
}

int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    return AdapterMock::ActionLnnGetLocalNum64Info(key, info);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return AdapterMock::ActionLnnGetLocalStrInfo(key, info, len);
}

int32_t LnnGetLocalNumInfoByIfnameIdx(InfoKey key, int32_t *info, int32_t ifIdx)
{
    return AdapterMock::ActionLnnGetLocalNumInfoByIfnameIdx(key, info, ifIdx);
}

int32_t LnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    return AdapterMock::ActionLnnGetLocalStrInfoByIfnameIdx(key, info, len, ifIdx);
}

int32_t AdapterMock::ActionRegisterServiceDataV2(const struct NSTACKX_ServiceData *param, uint32_t cnt)
{
    if (cnt == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

int32_t AdapterMock::ActionLnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t deviceType = 14;
    if (key == NUM_KEY_DEV_TYPE_ID) {
        *info = deviceType;
    }
    return SOFTBUS_OK;
}

int32_t AdapterMock::ActionLnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    int64_t accountId = 1234567890;
    if (key == NUM_KEY_ACCOUNT_LONG) {
        *info = accountId;
    }
    return SOFTBUS_OK;
}

int32_t AdapterMock::ActionLnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (key == STRING_KEY_DEV_UDID) {
        (void)strncpy_s(info, len, "ABCDEF11223344556677889900", len);
    }
    if (key == STRING_KEY_DEV_NAME) {
        (void)strncpy_s(info, len, "deviceName", len);
    }
    return SOFTBUS_OK;
}

int32_t AdapterMock::ActionLnnGetLocalNumInfoByIfnameIdx(InfoKey key, int32_t *info, int32_t ifIdx)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t port = 1234;
    if (key == NUM_KEY_AUTH_PORT) {
        *info = port;
    }
    return SOFTBUS_OK;
}

int32_t AdapterMock::ActionLnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (key == STRING_KEY_IP) {
        (void)strncpy_s(info, len, "192.168.0.1", len);
    }
    if (key == STRING_KEY_NET_IF_NAME) {
        (void)strncpy_s(info, len, "wlan0", len);
    }
    return SOFTBUS_OK;
}

void AdapterMock::SetupSuccessStub()
{
    EXPECT_CALL(*this, NSTACKX_RegisterServiceDataV2).WillRepeatedly(AdapterMock::ActionRegisterServiceDataV2);
    EXPECT_CALL(*this, LnnGetLocalNumInfo).WillRepeatedly(AdapterMock::ActionLnnGetLocalNumInfo);
    EXPECT_CALL(*this, LnnGetLocalNum64Info).WillRepeatedly(AdapterMock::ActionLnnGetLocalNum64Info);
    EXPECT_CALL(*this, LnnGetLocalStrInfo).WillRepeatedly(AdapterMock::ActionLnnGetLocalStrInfo);
    EXPECT_CALL(*this, LnnGetLocalNumInfoByIfnameIdx).
        WillRepeatedly(AdapterMock::ActionLnnGetLocalNumInfoByIfnameIdx);
    EXPECT_CALL(*this, LnnGetLocalStrInfoByIfnameIdx).
        WillRepeatedly(AdapterMock::ActionLnnGetLocalStrInfoByIfnameIdx);
}