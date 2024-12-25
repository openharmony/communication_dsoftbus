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

#ifndef DSOFTBUS_USB_MOCK_H
#define DSOFTBUS_USB_MOCK_H

#include "gmock/gmock.h"
#include "disc_usb_dispatcher.h"

class UsbMockInterface {
public:
    virtual DiscoveryFuncInterface* DiscUsbDispatcherInit(DiscInnerCallback *callback) = 0;
    virtual int32_t Publish(const PublishOption *option) = 0;
    virtual int32_t StartScan(const PublishOption *option) = 0;
    virtual int32_t Unpublish(const PublishOption *option) = 0;
    virtual int32_t StopScan(const PublishOption *option) = 0;
    virtual int32_t StartAdvertise(const SubscribeOption *option) = 0;
    virtual int32_t Subscribe(const SubscribeOption *option) = 0;
    virtual int32_t Unsubscribe(const SubscribeOption *option) = 0;
    virtual int32_t StopAdvertise(const SubscribeOption *option) = 0;
    virtual void LinkStatusChanged(LinkStatus status) = 0;
    virtual void UpdateLocalDeviceInfo(InfoTypeChanged type) = 0;
};

class UsbMock : UsbMockInterface {
public:
    static UsbMock* Get();
    static void InjectDeviceFoundEvent(const DeviceInfo *device);

    UsbMock();
    ~UsbMock();
    void SetupStub();

    MOCK_METHOD(DiscoveryFuncInterface*, DiscUsbDispatcherInit, (DiscInnerCallback* callback), (override));
    MOCK_METHOD(int32_t, Publish, (const PublishOption* option), (override));
    MOCK_METHOD(int32_t, StartScan, (const PublishOption* option), (override));
    MOCK_METHOD(int32_t, Unpublish, (const PublishOption* option), (override));
    MOCK_METHOD(int32_t, StopScan, (const PublishOption* option), (override));
    MOCK_METHOD(int32_t, StartAdvertise, (const SubscribeOption* option), (override));
    MOCK_METHOD(int32_t, Subscribe, (const SubscribeOption* option), (override));
    MOCK_METHOD(int32_t, StopAdvertise, (const SubscribeOption* option), (override));
    MOCK_METHOD(int32_t, Unsubscribe, (const SubscribeOption* option), (override));
    MOCK_METHOD(void, LinkStatusChanged, (LinkStatus status), (override));
    MOCK_METHOD(void, UpdateLocalDeviceInfo, (InfoTypeChanged type), (override));

    static inline bool callLnnStatus = false;

private:
    static int32_t UsbPublish(const PublishOption *option);
    static int32_t UsbStartScan(const PublishOption *option);
    static int32_t UsbUnpublish(const PublishOption *option);
    static int32_t UsbStopScan(const PublishOption *option);
    static int32_t UsbStartAdvertise(const SubscribeOption *option);
    static int32_t UsbSubscribe(const SubscribeOption *option);
    static int32_t UsbUnsubscribe(const SubscribeOption *option);
    static int32_t UsbStopAdvertise(const SubscribeOption *option);
    static void UsbLinkStatusChanged(LinkStatus status);
    static void UsbUpdateLocalDeviceInfo(InfoTypeChanged type);

    static inline DiscoveryFuncInterface interface_ = {
        UsbPublish, UsbStartScan, UsbUnpublish, UsbStopScan,
        UsbStartAdvertise, UsbSubscribe, UsbUnsubscribe, UsbStopAdvertise,
        UsbLinkStatusChanged, UsbUpdateLocalDeviceInfo,
    };
    static inline UsbMock* instance_;
    static inline DiscInnerCallback deviceFoundCallback_;
};
#endif