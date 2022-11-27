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

#ifndef DSOFTBUS_COAP_MOCK_H
#define DSOFTBUS_COAP_MOCK_H

#include "gmock/gmock.h"
#include "disc_coap.h"

class CoapMockInterface {
public:
    virtual DiscoveryFuncInterface* DiscCoapInit(DiscInnerCallback *callback) = 0;
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

class CoapMock : CoapMockInterface {
public:
    static CoapMock* Get();

    CoapMock();
    ~CoapMock();
    void SetupStub();

    MOCK_METHOD(DiscoveryFuncInterface*, DiscCoapInit, (DiscInnerCallback* callback), (override));
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

private:
    static int32_t CoapPublish(const PublishOption *option);
    static int32_t CoapStartScan(const PublishOption *option);
    static int32_t CoapUnpublish(const PublishOption *option);
    static int32_t CoapStopScan(const PublishOption *option);
    static int32_t CoapStartAdvertise(const SubscribeOption *option);
    static int32_t CoapSubscribe(const SubscribeOption *option);
    static int32_t CoapUnsubscribe(const SubscribeOption *option);
    static int32_t CoapStopAdvertise(const SubscribeOption *option);
    static void CoapLinkStatusChanged(LinkStatus status);
    static void CoapUpdateLocalDeviceInfo(InfoTypeChanged type);

    static inline DiscoveryFuncInterface interface_ = {
        CoapPublish, CoapStartScan, CoapUnpublish, CoapStopScan,
        CoapStartAdvertise, CoapSubscribe, CoapUnsubscribe, CoapStopAdvertise,
        CoapLinkStatusChanged, CoapUpdateLocalDeviceInfo,
    };
    static inline CoapMock* instance_;
    static inline DiscInnerCallback deviceFoundCallback_;
};
#endif