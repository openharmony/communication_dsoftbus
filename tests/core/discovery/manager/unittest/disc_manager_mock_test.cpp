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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "disc_interface.h"
#include "disc_manager.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "ble_mock.h"
#include "coap_mock.h"
#include "exception_branch_checker.h"

using namespace testing::ext;
using testing::Return;

namespace OHOS {
class DiscManagerMockTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}

    static void TearDownTestCase()
    {}

    void SetUp() override
    {}

    void TearDown() override
    {}

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
    static inline const char *largePackageName_ =
        "aaaaaaaaabbbbbbbbccccccccddddddddaaaaaaaaabbbbbbbbccccccccdddddddde";
};

/*
* @tc.name: DiscManagerInit001
* @tc.desc: discovery manager init failed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscManagerInit001, TestSize.Level1)
{
    DLOGI("DiscManagerInit001 begin ----");
    BleMock bleMock;
    bleMock.SetupStub();
    EXPECT_CALL(bleMock, DiscBleInit).WillRepeatedly(Return(nullptr));
    CoapMock coapMock;
    coapMock.SetupStub();
    EXPECT_CALL(coapMock, DiscCoapInit).WillRepeatedly(Return(nullptr));

    EXPECT_EQ(DiscMgrInit(), SOFTBUS_ERR);
    DLOGI("DiscManagerInit001 end ----");
}

/*
* @tc.name: DiscManagerInit002
* @tc.desc: discovery manager init success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscManagerInit002, TestSize.Level1)
{
    DLOGI("DiscManagerInit002 begin ----");
    BleMock bleMock;
    bleMock.SetupStub();
    CoapMock coapMock;
    coapMock.SetupStub();

    EXPECT_EQ(DiscMgrInit(), SOFTBUS_OK);
    DLOGI("DiscManagerInit002 end ----");
}

/*
* @tc.name: ClientDeathCallback001
* @tc.desc: client death callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, ClientDeathCallback001, TestSize.Level1)
{
    DLOGI("ClientDeathCallback001 begin ----");
    {
        ExceptionBranchChecker checker("pkgName is null");
        DiscMgrDeathCallback(nullptr);
        EXPECT_EQ(checker.GetResult(), true);
    }
    {
        ExceptionBranchChecker checker("Test is dead");
        DiscMgrDeathCallback("Test");
        EXPECT_EQ(checker.GetResult(), true);
    }
    DLOGI("ClientDeathCallback001 end ----");
}

/*
* @tc.name: DiscSetDiscoverCallback001
* @tc.desc: set discovery callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscSetDiscoverCallback001, TestSize.Level1)
{
    DLOGI("DiscSetDiscoverCallback001 begin ----");
    EXPECT_EQ(DiscSetDiscoverCallback(static_cast<DiscModule>(0), &innerCallback_), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscSetDiscoverCallback(static_cast<DiscModule>(MODULE_MAX + 1), &innerCallback_), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscSetDiscoverCallback(MODULE_LNN, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscSetDiscoverCallback(MODULE_LNN, &innerCallback_), SOFTBUS_OK);
    DLOGI("DiscSetDiscoverCallback001 end ----");
}

/*
* @tc.name: DiscPublish001
* @tc.desc: invalid parameters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscPublish001, TestSize.Level1)
{
    DLOGI("DiscPublish001 begin ----");
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

    DLOGI("DiscPublish001 end ----");
}

/*
* @tc.name: DiscPublish002
* @tc.desc: inner active publish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscPublish002, TestSize.Level1)
{
    DLOGI("DiscPublish002 begin ----");
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
        EXPECT_CALL(bleMock, Publish).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_EQ(DiscPublish(MODULE_LNN, &info), SOFTBUS_ERR);
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
        EXPECT_CALL(coapMock, Publish).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_EQ(DiscPublish(MODULE_LNN, &info), SOFTBUS_ERR);
    }

    info.publishId = PUBLISH_ID3;
    {
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_EQ(DiscPublish(MODULE_LNN, &info), SOFTBUS_OK);
    }
    DLOGI("DiscPublish002 end ----");
}

/*
* @tc.name: DiscStartScan001
* @tc.desc: invalid parameters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscStartScan001, TestSize.Level1)
{
    DLOGI("DiscStartScan001 begin ----");
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

    DLOGI("DiscStartScan001 end ----");
}

/*
* @tc.name: DiscStartScan002
* @tc.desc: inner passive publish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscStartScan002, TestSize.Level1)
{
    DLOGI("DiscStartScan002 begin ----");
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
        EXPECT_CALL(bleMock, StartScan).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_EQ(DiscStartScan(MODULE_LNN, &info), SOFTBUS_ERR);
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
        EXPECT_CALL(coapMock, StartScan).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_EQ(DiscStartScan(MODULE_LNN, &info), SOFTBUS_ERR);
    }

    info.publishId = PUBLISH_ID7;
    {
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_EQ(DiscStartScan(MODULE_LNN, &info), SOFTBUS_OK);
    }
    DLOGI("DiscStartScan002 end ----");
}

/*
* @tc.name: DiscUnpublish001
* @tc.desc: cancel publish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscUnpublish001, TestSize.Level1)
{
    DLOGI("DiscUnpublish001 begin ----");
    EXPECT_EQ(DiscUnpublish(static_cast<DiscModule>(0), 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscUnpublish(static_cast<DiscModule>(MODULE_MAX + 1), 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscUnpublish(MODULE_LNN, -1), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE);

    {
        BleMock bleMock;
        bleMock.SetupStub();
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_CALL(bleMock, Unpublish).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_CALL(bleMock, StopScan).WillRepeatedly(Return(SOFTBUS_ERR));

        EXPECT_EQ(DiscUnpublish(MODULE_LNN, PUBLISH_ID1), SOFTBUS_ERR);
        EXPECT_EQ(DiscUnpublish(MODULE_LNN, PUBLISH_ID5), SOFTBUS_ERR);
    }
    {
        BleMock bleMock;
        bleMock.SetupStub();
        CoapMock coapMock;
        coapMock.SetupStub();

        EXPECT_EQ(DiscUnpublish(MODULE_LNN, PUBLISH_ID3), SOFTBUS_OK);
        EXPECT_EQ(DiscUnpublish(MODULE_LNN, PUBLISH_ID7), SOFTBUS_OK);
    }

    DLOGI("DiscUnpublish001 end ----");
}

/*
* @tc.name: DiscStartAdvertise001
* @tc.desc: inner active subscribe
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscStartAdvertise001, TestSize.Level1)
{
    DLOGI("DiscStartAdvertise001 begin ----");
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

    DLOGI("DiscStartAdvertise001 end ----");
}

/*
* @tc.name: DiscStartAdvertise002
* @tc.desc: inner active subscribe
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscStartAdvertise002, TestSize.Level1)
{
    DLOGI("DiscStartAdvertise002 begin ----");
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
        EXPECT_CALL(bleMock, StartAdvertise).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_ERR);
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
        EXPECT_CALL(coapMock, StartAdvertise).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_ERR);
    }

    info.subscribeId = SUBSCRIBE_ID3;
    {
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_EQ(DiscStartAdvertise(MODULE_LNN, &info), SOFTBUS_OK);
    }
    DLOGI("DiscStartAdvertise002 end ----");
}

/*
* @tc.name: DiscSubscribe001
* @tc.desc: invalid parameters
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscSubscribe001, TestSize.Level1)
{
    DLOGI("DiscSubscribe001 begin ----");
    SubscribeInfo info;
    info.subscribeId = 0;
    EXPECT_EQ(DiscSubscribe(static_cast<DiscModule>(0), &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscSubscribe(static_cast<DiscModule>(MODULE_MAX + 1), &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscSubscribe(MODULE_LNN, nullptr), SOFTBUS_INVALID_PARAM);

    info.mode = DISCOVER_MODE_ACTIVE;
    EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_INVALID_PARAM);

    info.mode = DISCOVER_MODE_PASSIVE;
    info.medium = USB;
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

    DLOGI("DiscSubscribe001 end ----");
}

/*
* @tc.name: DiscSubscribe002
* @tc.desc: inner passive subscribe
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscSubscribe002, TestSize.Level1)
{
    DLOGI("DiscSubscribe002 begin ----");
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
        EXPECT_CALL(bleMock, Subscribe).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_ERR);
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
        EXPECT_CALL(coapMock, Subscribe).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_ERR);
    }

    info.subscribeId = SUBSCRIBE_ID7;
    {
        CoapMock coapMock;
        coapMock.SetupStub();
        EXPECT_EQ(DiscSubscribe(MODULE_LNN, &info), SOFTBUS_OK);
    }
    DLOGI("DiscSubscribe002 end ----");
}

/*
* @tc.name: DiscStopAdvertise001
* @tc.desc: stop advertise
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscStopAdvertise001, TestSize.Level1)
{
    DLOGI("DiscStopAdvertise001 begin ----");
    EXPECT_EQ(DiscStopAdvertise(static_cast<DiscModule>(0), 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStopAdvertise(static_cast<DiscModule>(MODULE_MAX + 1), 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStopAdvertise(MODULE_LNN, -1), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE);

    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_CALL(bleMock, StopAdvertise).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_CALL(bleMock, Unsubscribe).WillRepeatedly(Return(SOFTBUS_ERR));

        EXPECT_EQ(DiscStopAdvertise(MODULE_LNN, SUBSCRIBE_ID1), SOFTBUS_ERR);
        EXPECT_EQ(DiscStopAdvertise(MODULE_LNN, SUBSCRIBE_ID5), SOFTBUS_ERR);
    }
    {
        CoapMock coapMock;
        coapMock.SetupStub();

        EXPECT_EQ(DiscStopAdvertise(MODULE_LNN, SUBSCRIBE_ID3), SOFTBUS_OK);
        EXPECT_EQ(DiscStopAdvertise(MODULE_LNN, SUBSCRIBE_ID7), SOFTBUS_OK);
    }

    DLOGI("DiscStopAdvertise001 end ----");
}

/*
* @tc.name: DiscPublishService001
* @tc.desc: active publish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscPublishService001, TestSize.Level1)
{
    DLOGI("DiscPublishService001 begin ----");
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
        EXPECT_CALL(bleMock, Publish).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_EQ(DiscPublishService(packageName_, &info), SOFTBUS_ERR);
    }
    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_EQ(DiscPublishService(packageName_, &info), SOFTBUS_OK);
        EXPECT_EQ(DiscPublishService(packageName_, &info), SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM);
    }

    DLOGI("DiscPublishService001 end ----");
}

/*
* @tc.name: DiscUnPublishService001
* @tc.desc: cancel publish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscUnPublishService001, TestSize.Level1)
{
    DLOGI("DiscUnPublishService001 begin ----");

    EXPECT_EQ(DiscUnPublishService(nullptr, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscUnPublishService(largePackageName_, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscUnPublishService(packageName_, -1), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE);

    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_CALL(bleMock, Unpublish).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_EQ(DiscUnPublishService(packageName_, PUBLISH_ID8), SOFTBUS_ERR);
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

    DLOGI("DiscUnPublishService001 end ----");
}

/*
* @tc.name: DiscStartDiscovery001
* @tc.desc: start active discovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscStartDiscovery001, TestSize.Level1)
{
    DLOGI("DiscPublishService001 begin ----");
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
        EXPECT_CALL(bleMock, StartAdvertise).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_EQ(DiscStartDiscovery(packageName_, &info, &serverCallback_), SOFTBUS_ERR);
    }

    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_EQ(DiscStartDiscovery(packageName_, &info, &serverCallback_), SOFTBUS_OK);
        EXPECT_EQ(DiscStartDiscovery(packageName_, &info, &serverCallback_), SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM);
    }

    DLOGI("DiscStartDiscovery001 end ----");
}

/*
* @tc.name: DiscStopDiscovery001
* @tc.desc: stop discovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscStopDiscovery001, TestSize.Level1)
{
    DLOGI("DiscStopDiscovery001 begin ----");

    EXPECT_EQ(DiscStopDiscovery(nullptr, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStopDiscovery(largePackageName_, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscStopDiscovery(packageName_, -1), SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE);

    {
        BleMock bleMock;
        bleMock.SetupStub();
        EXPECT_CALL(bleMock, StopAdvertise).WillRepeatedly(Return(SOFTBUS_ERR));
        EXPECT_EQ(DiscStopDiscovery(packageName_, SUBSCRIBE_ID8), SOFTBUS_ERR);
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

    DLOGI("DiscStopDiscovery001 end ----");
}

/*
* @tc.name: DiscMgrDeathCallback001
* @tc.desc: client death handler
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscMgrDeathCallback001, TestSize.Level1)
{
    DLOGI("DiscMgrDeathCallback001 begin ----");
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
        SetCallLnnStatus(true);
        DiscMgrDeathCallback(packageName1_);

        DeviceInfo deviceInfo;
        deviceInfo.capabilityBitmapNum = 1;
        deviceInfo.capabilityBitmap[0] = 1 << OSD_CAPABILITY_BITMAP;
        BleMock::InjectDeviceFoundEvent(&deviceInfo);
        EXPECT_EQ(callbackPackageName_, packageName_);
        EXPECT_EQ(deviceInfo_.capabilityBitmapNum, deviceInfo.capabilityBitmapNum);
        EXPECT_EQ(innerDeviceInfo_.capabilityBitmapNum, deviceInfo.capabilityBitmapNum);
    }
    DLOGI("DiscMgrDeathCallback001 end ----");
}

/*
* @tc.name: DiscManagerDeinit001
* @tc.desc: discovery manager init success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscManagerMockTest, DiscManagerDeinit001, TestSize.Level1)
{
    DLOGI("DiscManagerDeinit001 begin ----");
    BleMock bleMock;
    bleMock.SetupStub();
    CoapMock coapMock;
    coapMock.SetupStub();

    ExceptionBranchChecker checker("disc manager deinit success");
    DiscMgrDeinit();
    EXPECT_EQ(checker.GetResult(), true);
    DLOGI("DiscManagerDeinit001 end ----");
}
}