/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <csignal>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

#include "ble_mock.h"
#include "coap_mock.h"
#include "disc_interface.h"
#include "disc_log.h"
#include "disc_manager.h"
#include "softbus_error_code.h"
#include "usb_mock.h"

using namespace testing::ext;
using testing::Return;

namespace {
uint32_t g_segmentFaultCount = 0;

void SignalHandler(int32_t sig, siginfo_t *info, void *context)
{
    (void)sig;
    (void)info;
    (void)context;
    g_segmentFaultCount++;
}
} // namespace

namespace OHOS {
class DiscManagerMockTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    void SetUp() override { }

    void TearDown() override { }

    static void OnDeviceFoundInner(const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
    {
        innerDeviceInfo_ = *device;
    }

    static int32_t OnDeviceFound(const char *packageName, const DeviceInfo *device,
                                 const InnerDeviceInfoAddtions *additions)
    {
        callbackPackageName_ = packageName;
        deviceInfo_ = *device;
        return SOFTBUS_OK;
    }

    static inline DiscInnerCallback innerCallback_ { OnDeviceFoundInner };
    static inline IServerDiscInnerCallback serverCallback_ { OnDeviceFound };
    static inline DeviceInfo innerDeviceInfo_;
    static inline DeviceInfo deviceInfo_;

    static constexpr int32_t PUBLISH_ID1 = 1;
    static constexpr int32_t PUBLISH_ID2 = 2;
    static constexpr int32_t PUBLISH_ID3 = 3;
    static constexpr int32_t PUBLISH_ID4 = 4;
    static constexpr int32_t PUBLISH_ID5 = 5;
    static constexpr int32_t PUBLISH_ID6 = 6;
    static constexpr int32_t PUBLISH_ID7 = 7;
    static constexpr int32_t PUBLISH_ID8 = 8;

    static constexpr int32_t SUBSCRIBE_ID1 = 1;
    static constexpr int32_t SUBSCRIBE_ID2 = 2;
    static constexpr int32_t SUBSCRIBE_ID3 = 3;
    static constexpr int32_t SUBSCRIBE_ID4 = 4;
    static constexpr int32_t SUBSCRIBE_ID5 = 5;
    static constexpr int32_t SUBSCRIBE_ID6 = 6;
    static constexpr int32_t SUBSCRIBE_ID7 = 7;
    static constexpr int32_t SUBSCRIBE_ID8 = 8;

    static inline std::string callbackPackageName_;
    static inline const char *packageName_ = "TestPackage";
    static inline const char *packageName1_ = "TestPackage1";
    static inline const char *largePackageName_ = "aaaaaaaaabbbbbbbbccccccccddddddddaaaaaaaaabbbbbbbbccccccccdddddddde";
};

/*
 * @tc.name: DiscManagerInit001
 * @tc.desc: discovery manager init failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscManagerInit001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscManagerInit001 begin ----");
    BleMock bleMock;
    bleMock.SetupStub();
    EXPECT_CALL(bleMock, DiscBleInit).WillRepeatedly(Return(nullptr));
    CoapMock coapMock;
    coapMock.SetupStub();
    EXPECT_CALL(coapMock, DiscCoapInit).WillRepeatedly(Return(nullptr));
    UsbMock usbMock;
    usbMock.SetupStub();
    EXPECT_CALL(usbMock, DiscUsbDispatcherInit).WillRepeatedly(Return(nullptr));

    EXPECT_NE(DiscMgrInit(), SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscManagerInit001 end ----");
}

/*
 * @tc.name: DiscManagerInit002
 * @tc.desc: discovery manager init success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscManagerInit002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscManagerInit002 begin ----");
    BleMock bleMock;
    bleMock.SetupStub();
    CoapMock coapMock;
    coapMock.SetupStub();
    UsbMock usbMock;
    usbMock.SetupStub();

    EXPECT_EQ(DiscMgrInit(), SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscManagerInit002 end ----");
}

/*
 * @tc.name: DiscSetDiscoverCallback001
 * @tc.desc: set discovery callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscSetDiscoverCallback001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSetDiscoverCallback001 begin ----");
    EXPECT_EQ(DiscSetDiscoverCallback(static_cast<DiscModule>(0), &innerCallback_), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscSetDiscoverCallback(static_cast<DiscModule>(MODULE_MAX + 1), &innerCallback_), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscSetDiscoverCallback(MODULE_LNN, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscSetDiscoverCallback(MODULE_LNN, &innerCallback_), SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSetDiscoverCallback001 end ----");
}

/*
 * @tc.name: DiscPublish001
 * @tc.desc: invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscPublish001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscPublish001 begin ----");
    PublishInfo info;
    info.publishId = 0;
    EXPECT_EQ(DiscPublish(static_cast<DiscModule>(0), &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscPublish(static_cast<DiscModule>(MODULE_MAX + 1), &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscPublish(MODULE_LNN, nullptr), SOFTBUS_INVALID_PARAM);

    info.mode = DISCOVER_MODE_PASSIVE;
    EXPECT_EQ(DiscPublish(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.mode = DISCOVER_MODE_ACTIVE;
    info.medium = USB;
    EXPECT_EQ(DiscPublish(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.medium = BLE;
    info.freq = FREQ_BUTT;
    EXPECT_EQ(DiscPublish(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.freq = LOW;
    info.capabilityData = nullptr;
    info.dataLen = 10;
    EXPECT_EQ(DiscPublish(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.capabilityData = nullptr;
    info.dataLen = 0;
    info.capability = "test";
    EXPECT_EQ(DiscPublish(MODULE_LNN, &info), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE);

    DISC_LOGI(DISC_TEST, "DiscPublish001 end ----");
}

/*
 * @tc.name: DiscPublish002
 * @tc.desc: inner active publish
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscPublish002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscPublish002 begin ----");
    PublishInfo info;
    info.publishId = 0;
    info.mode = DISCOVER_MODE_ACTIVE;
    info.medium = BLE;
    info.freq = LOW;
    info.capabilityData = (uint8_t *)"test";
    info.dataLen = 4;
    info.capability = "osdCapability";

    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_CALL(bleMock, Publish).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscPublish(MODULE_LNN, &info), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }

    info.publishId = PUBLISH_ID1;
    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_EQ(DiscPublish(MODULE_LNN, &info), SOFTBUS_OK);
    }

    info.publishId = PUBLISH_ID2;
    info.medium = COAP;
    {
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_CALL(coapMock, Publish).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscPublish(MODULE_LNN, &info), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }

    info.publishId = PUBLISH_ID3;
    {
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_EQ(DiscPublish(MODULE_LNN, &info), SOFTBUS_OK);
    }
    DISC_LOGI(DISC_TEST, "DiscPublish002 end ----");
}

/*
 * @tc.name: DiscStartScan001
 * @tc.desc: invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscStartScan001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscStartScan001 begin ----");
    PublishInfo info;
    info.publishId = 0;
    EXPECT_EQ(DiscStartScan(static_cast<DiscModule>(0), &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStartScan(static_cast<DiscModule>(MODULE_MAX + 1), &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStartScan(MODULE_LNN, nullptr), SOFTBUS_INVALID_PARAM);

    info.mode = DISCOVER_MODE_ACTIVE;
    EXPECT_EQ(DiscStartScan(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.mode = DISCOVER_MODE_PASSIVE;
    info.medium = USB;
    EXPECT_EQ(DiscStartScan(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.medium = BLE;
    info.freq = FREQ_BUTT;
    EXPECT_EQ(DiscStartScan(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.freq = LOW;
    info.capabilityData = nullptr;
    info.dataLen = 10;
    EXPECT_EQ(DiscStartScan(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.capabilityData = nullptr;
    info.dataLen = 0;
    info.capability = "test";
    EXPECT_EQ(DiscStartScan(MODULE_LNN, &info), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE);

    DISC_LOGI(DISC_TEST, "DiscStartScan001 end ----");
}

/*
 * @tc.name: DiscStartScan002
 * @tc.desc: inner passive publish
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscStartScan002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscStartScan002 begin ----");
    PublishInfo info;
    info.publishId = 0;
    info.mode = DISCOVER_MODE_PASSIVE;
    info.medium = BLE;
    info.freq = LOW;
    info.capabilityData = (uint8_t *)"test";
    info.dataLen = 4;
    info.capability = "osdCapability";

    info.publishId = PUBLISH_ID4;
    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_CALL(bleMock, StartScan).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscStartScan(MODULE_LNN, &info), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }

    info.publishId = PUBLISH_ID5;
    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_EQ(DiscStartScan(MODULE_LNN, &info), SOFTBUS_OK);
    }

    info.publishId = PUBLISH_ID6;
    info.medium = COAP;
    {
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_CALL(coapMock, StartScan).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscStartScan(MODULE_LNN, &info), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }

    info.publishId = PUBLISH_ID7;
    {
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_EQ(DiscStartScan(MODULE_LNN, &info), SOFTBUS_OK);
    }
    DISC_LOGI(DISC_TEST, "DiscStartScan002 end ----");
}

/*
 * @tc.name: DiscUnpublish001
 * @tc.desc: cancel publish
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscUnpublish001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscUnpublish001 begin ----");
    EXPECT_EQ(DiscUnpublish(static_cast<DiscModule>(0), 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscUnpublish(static_cast<DiscModule>(MODULE_MAX + 1), 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscUnpublish(MODULE_LNN, -1), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE);

    {
        BleMock bleMock;
        bleMock.SetupStub();
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_CALL(bleMock, Unpublish).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_CALL(bleMock, StopScan).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));

        EXPECT_EQ(DiscUnpublish(MODULE_LNN, PUBLISH_ID1), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
        EXPECT_EQ(DiscUnpublish(MODULE_LNN, PUBLISH_ID5), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }
    {
        BleMock bleMock;
        bleMock.SetupStub();
        CoapMock coapMock;
        coapMock.SetupStub();

        EXPECT_EQ(DiscUnpublish(MODULE_LNN, PUBLISH_ID3), SOFTBUS_OK);
        EXPECT_EQ(DiscUnpublish(MODULE_LNN, PUBLISH_ID7), SOFTBUS_OK);
    }

    DISC_LOGI(DISC_TEST, "DiscUnpublish001 end ----");
}

/*
 * @tc.name: DiscStartAdvertise001
 * @tc.desc: inner active subscribe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscStartAdvertise001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscStartAdvertise001 begin ----");
    SubscribeInfo info;
    info.subscribeId = 0;
    EXPECT_EQ(DiscStartAdvertise(static_cast<DiscModule>(0), &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStartAdvertise(static_cast<DiscModule>(MODULE_MAX + 1), &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, nullptr), SOFTBUS_INVALID_PARAM);

    info.mode = DISCOVER_MODE_PASSIVE;
    EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.mode = DISCOVER_MODE_ACTIVE;
    info.medium = USB;
    EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.medium = BLE;
    info.freq = FREQ_BUTT;
    EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.freq = LOW;
    info.capabilityData = nullptr;
    info.dataLen = 10;
    EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.capabilityData = nullptr;
    info.dataLen = 0;
    info.capability = "test";
    EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE);

    DISC_LOGI(DISC_TEST, "DiscStartAdvertise001 end ----");
}

/*
 * @tc.name: DiscStartAdvertise002
 * @tc.desc: inner active subscribe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscStartAdvertise002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscStartAdvertise002 begin ----");
    SubscribeInfo info;
    info.subscribeId = 0;
    info.mode = DISCOVER_MODE_ACTIVE;
    info.medium = BLE;
    info.freq = LOW;
    info.capabilityData = (uint8_t *)"test";
    info.dataLen = 4;
    info.capability = "osdCapability";

    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_CALL(bleMock, StartAdvertise).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }

    info.subscribeId = SUBSCRIBE_ID1;
    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_OK);
    }

    info.subscribeId = SUBSCRIBE_ID2;
    info.medium = COAP;
    {
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_CALL(coapMock, StartAdvertise).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }

    info.subscribeId = SUBSCRIBE_ID3;
    {
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_OK);
    }
    DISC_LOGI(DISC_TEST, "DiscStartAdvertise002 end ----");
}

/*
 * @tc.name: DiscSubscribe001
 * @tc.desc: invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscSubscribe001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSubscribe001 begin ----");
    SubscribeInfo info;
    info.subscribeId = 0;
    EXPECT_EQ(DiscSubscribe(static_cast<DiscModule>(0), &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscSubscribe(static_cast<DiscModule>(MODULE_MAX + 1), &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscSubscribe(MODULE_LNN, nullptr), SOFTBUS_INVALID_PARAM);

    info.mode = DISCOVER_MODE_ACTIVE;
    EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.mode = DISCOVER_MODE_PASSIVE;
    info.medium = COAP1;
    EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.medium = BLE;
    info.freq = FREQ_BUTT;
    EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.freq = LOW;
    info.capabilityData = nullptr;
    info.dataLen = 10;
    EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.capabilityData = nullptr;
    info.dataLen = 0;
    info.capability = "test";
    EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE);

    DISC_LOGI(DISC_TEST, "DiscSubscribe001 end ----");
}

/*
 * @tc.name: DiscSubscribe002
 * @tc.desc: inner passive subscribe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscSubscribe002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSubscribe002 begin ----");
    SubscribeInfo info;
    info.subscribeId = 0;
    info.mode = DISCOVER_MODE_PASSIVE;
    info.medium = BLE;
    info.freq = LOW;
    info.capabilityData = (uint8_t *)"test";
    info.dataLen = 4;
    info.capability = "osdCapability";

    info.subscribeId = SUBSCRIBE_ID4;
    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_CALL(bleMock, Subscribe).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }

    info.subscribeId = SUBSCRIBE_ID5;
    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_OK);
    }

    info.subscribeId = SUBSCRIBE_ID6;
    info.medium = COAP;
    {
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_CALL(coapMock, Subscribe).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }

    info.subscribeId = SUBSCRIBE_ID7;
    {
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_OK);
    }
    DISC_LOGI(DISC_TEST, "DiscSubscribe002 end ----");
}

/*
 * @tc.name: DiscStopAdvertise001
 * @tc.desc: stop advertise
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscStopAdvertise001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscStopAdvertise001 begin ----");
    EXPECT_EQ(DiscStopAdvertise(static_cast<DiscModule>(0), 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStopAdvertise(static_cast<DiscModule>(MODULE_MAX + 1), 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStopAdvertise(MODULE_LNN, -1), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE);

    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_CALL(bleMock, StopAdvertise).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_CALL(bleMock, Unsubscribe).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));

        EXPECT_EQ(DiscStopAdvertise(MODULE_LNN, SUBSCRIBE_ID1), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
        EXPECT_EQ(DiscStopAdvertise(MODULE_LNN, SUBSCRIBE_ID5), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }
    {
        CoapMock coapMock;
        coapMock.SetupStub();

        EXPECT_EQ(DiscStopAdvertise(MODULE_LNN, SUBSCRIBE_ID3), SOFTBUS_OK);
        EXPECT_EQ(DiscStopAdvertise(MODULE_LNN, SUBSCRIBE_ID7), SOFTBUS_OK);
    }

    DISC_LOGI(DISC_TEST, "DiscStopAdvertise001 end ----");
}

/*
 * @tc.name: DiscPublishService001
 * @tc.desc: active publish
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscPublishService001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscPublishService001 begin ----");
    PublishInfo info;
    info.medium = BLE;
    info.mode = DISCOVER_MODE_ACTIVE;
    info.freq = LOW;
    info.capability = "test";
    info.capabilityData = (uint8_t *)"test";
    info.dataLen = 4;

    EXPECT_EQ(DiscPublishService(nullptr, &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscPublishService(packageName_, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscPublishService(largePackageName_, &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscPublishService(packageName_, &info), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE);

    info.publishId = PUBLISH_ID8;
    info.capability = "osdCapability";
    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_CALL(bleMock, Publish).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscPublishService(packageName_, &info), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }
    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_EQ(DiscPublishService(packageName_, &info), SOFTBUS_OK);
        EXPECT_EQ(DiscPublishService(packageName_, &info), SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM);
    }

    DISC_LOGI(DISC_TEST, "DiscPublishService001 end ----");
}

/*
 * @tc.name: DiscUnPublishService001
 * @tc.desc: cancel publish
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscUnPublishService001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscUnPublishService001 begin ----");

    EXPECT_EQ(DiscUnPublishService(nullptr, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscUnPublishService(largePackageName_, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscUnPublishService(packageName_, -1), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE);

    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_CALL(bleMock, Unpublish).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscUnPublishService(packageName_, PUBLISH_ID8), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }

    {
        PublishInfo info;
        info.publishId = PUBLISH_ID8;
        info.medium = BLE;
        info.mode = DISCOVER_MODE_ACTIVE;
        info.freq = LOW;
        info.capability = "osdCapability";
        info.capabilityData = (uint8_t *)"test";
        info.dataLen = 4;

        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_EQ(DiscPublishService(packageName_, &info), SOFTBUS_OK);
        EXPECT_EQ(DiscUnPublishService(packageName_, PUBLISH_ID8), SOFTBUS_OK);
    }

    DISC_LOGI(DISC_TEST, "DiscUnPublishService001 end ----");
}

/*
 * @tc.name: DiscStartDiscovery001
 * @tc.desc: start active discovery
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscStartDiscovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscPublishService001 begin ----");
    SubscribeInfo info;
    info.medium = BLE;
    info.mode = DISCOVER_MODE_ACTIVE;
    info.freq = LOW;
    info.capability = "test";
    info.capabilityData = (uint8_t *)"test";
    info.dataLen = 4;

    EXPECT_EQ(DiscStartDiscovery(nullptr, &info, &serverCallback_), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStartDiscovery(largePackageName_, &info, &serverCallback_), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStartDiscovery(packageName_, nullptr, &serverCallback_), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStartDiscovery(packageName_, &info, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStartDiscovery(packageName_, &info, &serverCallback_), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE);

    info.subscribeId = SUBSCRIBE_ID8;
    info.capability = "osdCapability";
    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_CALL(bleMock, StartAdvertise).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscStartDiscovery(packageName_, &info, &serverCallback_), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
    }

    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_EQ(DiscStartDiscovery(packageName_, &info, &serverCallback_), SOFTBUS_OK);
        EXPECT_EQ(DiscStartDiscovery(packageName_, &info, &serverCallback_), SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM);
    }

    DISC_LOGI(DISC_TEST, "DiscStartDiscovery001 end ----");
}

/*
 * @tc.name: DiscStopDiscovery001
 * @tc.desc: stop discovery
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscStopDiscovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscStopDiscovery001 begin ----");

    EXPECT_EQ(DiscStopDiscovery(nullptr, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStopDiscovery(largePackageName_, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStopDiscovery(packageName_, -1), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE);

    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_CALL(bleMock, StopAdvertise).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscStopDiscovery(packageName_, SUBSCRIBE_ID8), SOFTBUS_DISCOVER_TEST_CASE_ERRCODE);
        EXPECT_EQ(DiscStopDiscovery(packageName_, SUBSCRIBE_ID8), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE);
    }

    {
        SubscribeInfo info;
        info.subscribeId = SUBSCRIBE_ID8;
        info.medium = BLE;
        info.mode = DISCOVER_MODE_ACTIVE;
        info.freq = LOW;
        info.capability = "osdCapability";
        info.capabilityData = (uint8_t *)"test";
        info.dataLen = 4;

        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_EQ(DiscStartDiscovery(packageName_, &info, &serverCallback_), SOFTBUS_OK);
        EXPECT_EQ(DiscStopDiscovery(packageName_, PUBLISH_ID8), SOFTBUS_OK);
        EXPECT_EQ(DiscStopDiscovery(packageName_, PUBLISH_ID8), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE);
    }

    DISC_LOGI(DISC_TEST, "DiscStopDiscovery001 end ----");
}

/*
 * @tc.name: DiscConcurrentRequests001
 * @tc.desc: test with concurrent requests
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscConcurrentRequests001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscConcurrentRequests001 begin ----");
    BleMock bleMock;
    bleMock.SetupStub();

    struct sigaction sa = {
        .sa_flags = SA_SIGINFO,
        .sa_sigaction = SignalHandler,
    };
    sigemptyset(&sa.sa_mask);
    ASSERT_NE(sigaction(SIGSEGV, &sa, nullptr), -1);

    SubscribeInfo subscribeInfo = {
        .subscribeId = 1,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "osdCapability",
    };
    PublishInfo publishInfo = {
        .publishId = 1,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "osdCapability",
    };

    uint32_t loopCount = 100;
    uint32_t waitSeconds = 10;
    g_segmentFaultCount = 0;
    for (uint32_t i = 0; i < loopCount; ++i) {
        std::thread(DiscStartDiscovery, packageName_, &subscribeInfo, &serverCallback_).detach();
        std::thread(DiscStopDiscovery, packageName_, subscribeInfo.subscribeId).detach();
        std::thread(DiscPublishService, packageName_, &publishInfo).detach();
        std::thread(DiscUnPublishService, packageName_, publishInfo.publishId).detach();

        std::thread(DiscStartAdvertise, MODULE_LNN, &subscribeInfo).detach();
        std::thread(DiscStopAdvertise, MODULE_LNN, subscribeInfo.subscribeId).detach();
        std::thread(DiscStartScan, MODULE_LNN, &publishInfo).detach();
        std::thread(DiscUnpublish, MODULE_LNN, publishInfo.publishId).detach();
    }

    std::this_thread::sleep_for(std::chrono::seconds(waitSeconds));
    EXPECT_EQ(g_segmentFaultCount, 0);
    DISC_LOGI(DISC_TEST, "DiscConcurrentRequests001 end ----");
}

/*
 * @tc.name: DiscMgrDeathCallback001
 * @tc.desc: client death handler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscMgrDeathCallback001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscMgrDeathCallback001 begin ----");
    {
        SubscribeInfo info;
        info.subscribeId = SUBSCRIBE_ID8;
        info.medium = BLE;
        info.mode = DISCOVER_MODE_ACTIVE;
        info.freq = LOW;
        info.capability = "osdCapability";
        info.capabilityData = (uint8_t *)"test";
        info.dataLen = 4;

        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_EQ(DiscStartDiscovery(packageName_, &info, &serverCallback_), SOFTBUS_OK);
        EXPECT_EQ(DiscStartDiscovery(packageName1_, &info, &serverCallback_), SOFTBUS_OK);
        EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_OK);
        EXPECT_EQ(DiscSetDiscoverCallback(MODULE_LNN, &innerCallback_), SOFTBUS_OK);
        DiscMgrDeathCallback(packageName1_);

        DeviceInfo deviceInfo;
        deviceInfo.capabilityBitmapNum = 1;
        deviceInfo.capabilityBitmap[0] = 1 << OSD_CAPABILITY_BITMAP;
        BleMock::InjectDeviceFoundEvent(&deviceInfo);
        EXPECT_EQ(callbackPackageName_, packageName_);
        EXPECT_EQ(deviceInfo_.capabilityBitmapNum, deviceInfo.capabilityBitmapNum);
        EXPECT_EQ(innerDeviceInfo_.capabilityBitmapNum, deviceInfo.capabilityBitmapNum);
    }
    DISC_LOGI(DISC_TEST, "DiscMgrDeathCallback001 end ----");
}

/*
 * @tc.name: DiscManagerDeinit001
 * @tc.desc: discovery manager init success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerMockTest, DiscManagerDeinit001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscManagerDeinit001 begin ----");
    BleMock bleMock;
    bleMock.SetupStub();
    CoapMock coapMock;
    coapMock.SetupStub();
    UsbMock usbMock;
    usbMock.SetupStub();

    EXPECT_EQ(DiscMgrInit(), SOFTBUS_OK);
    DiscMgrDeinit();
    DISC_LOGI(DISC_TEST, "DiscManagerDeinit001 end ----");
}
} // namespace OHOS