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

#ifndef DSOFTBUS_NFC_MOCK_H
#define DSOFTBUS_NFC_MOCK_H

#include "gmock/gmock.h"
#include "disc_nfc_dispatcher.h"

class NfcMockInterface {
public:
    virtual DiscoveryFuncInterface* DiscNfcDispatcherInit(DiscInnerCallback *callback) = 0;
    virtual int32_t Publish(const PublishOption *option) = 0;
    virtual int32_t StartScan(const PublishOption *option) = 0;
    virtual int32_t Unpublish(const PublishOption *option) = 0;
    virtual int32_t StopScan(const PublishOption *option) = 0;
    virtual int32_t StartAdvertise(const SubscribeOption *option) = 0;
    virtual int32_t Subscribe(const SubscribeOption *option) = 0;
    virtual int32_t Unsubscribe(const SubscribeOption *option) = 0;
    virtual int32_t StopAdvertise(const SubscribeOption *option) = 0;
    virtual void LinkStatusChanged(LinkStatus status, int32_t ifnameIdx) = 0;
    virtual void UpdateLocalDeviceInfo(InfoTypeChanged type) = 0;
};

class NfcMock : NfcMockInterface {
public:
    static NfcMock* Get();
    static void InjectDeviceFoundEvent(const DeviceInfo *device);

    NfcMock();
    ~NfcMock();
    void SetupStub();

    MOCK_METHOD(DiscoveryFuncInterface*, DiscNfcDispatcherInit, (DiscInnerCallback* callback), (override));
    MOCK_METHOD(int32_t, Publish, (const PublishOption* option), (override));
    MOCK_METHOD(int32_t, StartScan, (const PublishOption* option), (override));
    MOCK_METHOD(int32_t, Unpublish, (const PublishOption* option), (override));
    MOCK_METHOD(int32_t, StopScan, (const PublishOption* option), (override));
    MOCK_METHOD(int32_t, StartAdvertise, (const SubscribeOption* option), (override));
    MOCK_METHOD(int32_t, Subscribe, (const SubscribeOption* option), (override));
    MOCK_METHOD(int32_t, StopAdvertise, (const SubscribeOption* option), (override));
    MOCK_METHOD(int32_t, Unsubscribe, (const SubscribeOption* option), (override));
    MOCK_METHOD(void, LinkStatusChanged, (LinkStatus status, int32_t ifnameIdx), (override));
    MOCK_METHOD(void, UpdateLocalDeviceInfo, (InfoTypeChanged type), (override));

    static inline bool callLnnStatus = false;

private:
    static int32_t NfcPublish(const PublishOption *option);
    static int32_t NfcStartScan(const PublishOption *option);
    static int32_t NfcUnpublish(const PublishOption *option);
    static int32_t NfcStopScan(const PublishOption *option);
    static int32_t NfcStartAdvertise(const SubscribeOption *option);
    static int32_t NfcSubscribe(const SubscribeOption *option);
    static int32_t NfcUnsubscribe(const SubscribeOption *option);
    static int32_t NfcStopAdvertise(const SubscribeOption *option);
    static void NfcLinkStatusChanged(LinkStatus status, int32_t ifnameIdx);
    static void NfcUpdateLocalDeviceInfo(InfoTypeChanged type);

    static inline DiscoveryFuncInterface interface_ = {
        NfcPublish, NfcStartScan, NfcUnpublish, NfcStopScan,
        NfcStartAdvertise, NfcSubscribe, NfcUnsubscribe, NfcStopAdvertise,
        NfcLinkStatusChanged, NfcUpdateLocalDeviceInfo,
    };
    static inline NfcMock* instance_;
    static inline DiscInnerCallback deviceFoundCallback_;
};
#endif