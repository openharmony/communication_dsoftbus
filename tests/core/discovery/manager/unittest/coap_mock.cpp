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

#include "coap_mock.h"
#include "disc_log.h"
#include "softbus_error_code.h"

using testing::NotNull;
using testing::Return;

DiscoveryFuncInterface *DiscCoapInit(DiscInnerCallback *callback)
{
    return CoapMock::Get()->DiscCoapInit(callback);
}

void DiscCoapDeinit()
{
    DISC_LOGI(DISC_TEST, "destroy");
}

int32_t CoapMock::CoapPublish(const PublishOption *option)
{
    return Get()->Publish(option);
}

int32_t CoapMock::CoapStartScan(const PublishOption *option)
{
    return Get()->StartScan(option);
}

int32_t CoapMock::CoapUnpublish(const PublishOption *option)
{
    return CoapMock::Get()->Unpublish(option);
}

int32_t CoapMock::CoapStopScan(const PublishOption *option)
{
    return Get()->StopScan(option);
}

int32_t CoapMock::CoapStartAdvertise(const SubscribeOption *option)
{
    return Get()->StartAdvertise(option);
}

int32_t CoapMock::CoapSubscribe(const SubscribeOption *option)
{
    return Get()->Subscribe(option);
}

int32_t CoapMock::CoapUnsubscribe(const SubscribeOption *option)
{
    return Get()->Unsubscribe(option);
}

int32_t CoapMock::CoapStopAdvertise(const SubscribeOption *option)
{
    return Get()->StopAdvertise(option);
}

void CoapMock::CoapLinkStatusChanged(LinkStatus status)
{
    Get()->LinkStatusChanged(status);
}

void CoapMock::CoapUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    Get()->UpdateLocalDeviceInfo(type);
}

CoapMock* CoapMock::Get()
{
    return instance_;
}

CoapMock::CoapMock()
{
    instance_ = this;
}

CoapMock::~CoapMock()
{
    instance_ = nullptr;
}

void CoapMock::SetupStub()
{
    EXPECT_CALL(*this, DiscCoapInit(NotNull())).WillRepeatedly([](DiscInnerCallback *callback) {
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