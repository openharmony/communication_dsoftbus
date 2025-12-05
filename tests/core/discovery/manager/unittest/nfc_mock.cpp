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

#include "nfc_mock.h"
#include "disc_log.h"
#include "softbus_error_code.h"

using testing::NotNull;
using testing::Return;

DiscoveryFuncInterface *DiscNfcDispatcherInit(DiscInnerCallback *callback)
{
    return NfcMock::Get()->DiscNfcDispatcherInit(callback);
}

void DiscNfcDispatcherDeinit()
{
    DISC_LOGI(DISC_TEST, "destroy");
}

int32_t NfcMock::NfcPublish(const PublishOption *option)
{
    return Get()->Publish(option);
}

int32_t NfcMock::NfcStartScan(const PublishOption *option)
{
    return Get()->StartScan(option);
}

int32_t NfcMock::NfcUnpublish(const PublishOption *option)
{
    return Get()->Unpublish(option);
}

int32_t NfcMock::NfcStopScan(const PublishOption *option)
{
    return Get()->StopScan(option);
}

int32_t NfcMock::NfcStartAdvertise(const SubscribeOption *option)
{
    return Get()->StartAdvertise(option);
}

int32_t NfcMock::NfcSubscribe(const SubscribeOption *option)
{
    return Get()->Subscribe(option);
}

int32_t NfcMock::NfcUnsubscribe(const SubscribeOption *option)
{
    return Get()->Unsubscribe(option);
}

int32_t NfcMock::NfcStopAdvertise(const SubscribeOption *option)
{
    return Get()->StopAdvertise(option);
}

void NfcMock::NfcLinkStatusChanged(LinkStatus status, int32_t ifnameIdx)
{
    Get()->LinkStatusChanged(status, ifnameIdx);
}

void NfcMock::NfcUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    Get()->UpdateLocalDeviceInfo(type);
}

NfcMock* NfcMock::Get()
{
    return instance_;
}

NfcMock::NfcMock()
{
    instance_ = this;
}

NfcMock::~NfcMock()
{
    instance_ = nullptr;
}

void NfcMock::InjectDeviceFoundEvent(const DeviceInfo *device)
{
    if (deviceFoundCallback_.OnDeviceFound) {
        InnerDeviceInfoAddtions additions;
        additions.medium = NFC;
        deviceFoundCallback_.OnDeviceFound(device, &additions);
    }
}
void NfcMock::SetupStub()
{
    EXPECT_CALL(*this, DiscNfcDispatcherInit(NotNull())).WillRepeatedly([](DiscInnerCallback *callback) {
        deviceFoundCallback_ = *callback;
        return &interface_;
    });
    EXPECT_CALL(*this, Publish(NotNull())).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, StartScan(NotNull())).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, Unpublish(NotNull())).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, StopScan(NotNull())).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, StartAdvertise(NotNull())).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, Subscribe(NotNull())).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, Unsubscribe(NotNull())).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, StopAdvertise(NotNull())).WillRepeatedly(Return(SOFTBUS_OK));
}