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

#include "ble_mock.h"
#include "disc_log.h"
#include "softbus_error_code.h"

using testing::NotNull;
using testing::Return;

DiscoveryFuncInterface *DiscBleInit(DiscInnerCallback *callback)
{
    return BleMock::Get()->DiscBleInit(callback);
}

void DiscBleDeinit()
{
    DISC_LOGI(DISC_TEST, "destroy");
}

int32_t BleMock::BlePublish(const PublishOption *option)
{
    return Get()->Publish(option);
}

int32_t BleMock::BleStartScan(const PublishOption *option)
{
    return Get()->StartScan(option);
}

int32_t BleMock::BleUnpublish(const PublishOption *option)
{
    return Get()->Unpublish(option);
}

int32_t BleMock::BleStopScan(const PublishOption *option)
{
    return Get()->StopScan(option);
}

int32_t BleMock::BleStartAdvertise(const SubscribeOption *option)
{
    return Get()->StartAdvertise(option);
}

int32_t BleMock::BleSubscribe(const SubscribeOption *option)
{
    return Get()->Subscribe(option);
}

int32_t BleMock::BleUnsubscribe(const SubscribeOption *option)
{
    return Get()->Unsubscribe(option);
}

int32_t BleMock::BleStopAdvertise(const SubscribeOption *option)
{
    return Get()->StopAdvertise(option);
}

void BleMock::BleLinkStatusChanged(LinkStatus status)
{
    Get()->LinkStatusChanged(status);
}

void BleMock::BleUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    Get()->UpdateLocalDeviceInfo(type);
}

BleMock* BleMock::Get()
{
    return instance_;
}

BleMock::BleMock()
{
    instance_ = this;
}

BleMock::~BleMock()
{
    instance_ = nullptr;
}

void BleMock::InjectDeviceFoundEvent(const DeviceInfo *device)
{
    if (deviceFoundCallback_.OnDeviceFound) {
        InnerDeviceInfoAddtions additions;
        additions.medium = BLE;
        deviceFoundCallback_.OnDeviceFound(device, &additions);
    }
}
void BleMock::SetupStub()
{
    EXPECT_CALL(*this, DiscBleInit(NotNull())).WillRepeatedly([](DiscInnerCallback *callback) {
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
