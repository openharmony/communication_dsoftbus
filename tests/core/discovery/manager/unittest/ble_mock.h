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

#ifndef DSOFTBUS_BLE_MOCK_H
#define DSOFTBUS_BLE_MOCK_H

#include "gmock/gmock.h"
#include "disc_ble_dispatcher.h"

class BleMockInterface {
public:
    virtual DiscoveryFuncInterface* DiscBleInit(DiscInnerCallback *callback) = 0;
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

class BleMock : BleMockInterface {
public:
    static BleMock* Get();
    static void InjectDeviceFoundEvent(const DeviceInfo *device);

    BleMock();
    ~BleMock();
    void SetupStub();

    MOCK_METHOD(DiscoveryFuncInterface*, DiscBleInit, (DiscInnerCallback* callback), (override));
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
    static int32_t BlePublish(const PublishOption *option);
    static int32_t BleStartScan(const PublishOption *option);
    static int32_t BleUnpublish(const PublishOption *option);
    static int32_t BleStopScan(const PublishOption *option);
    static int32_t BleStartAdvertise(const SubscribeOption *option);
    static int32_t BleSubscribe(const SubscribeOption *option);
    static int32_t BleUnsubscribe(const SubscribeOption *option);
    static int32_t BleStopAdvertise(const SubscribeOption *option);
    static void BleLinkStatusChanged(LinkStatus status);
    static void BleUpdateLocalDeviceInfo(InfoTypeChanged type);

    static inline DiscoveryFuncInterface interface_ = {
        BlePublish, BleStartScan, BleUnpublish, BleStopScan,
        BleStartAdvertise, BleSubscribe, BleUnsubscribe, BleStopAdvertise,
        BleLinkStatusChanged, BleUpdateLocalDeviceInfo,
    };
    static inline BleMock* instance_;
    static inline DiscInnerCallback deviceFoundCallback_;
};
#endif