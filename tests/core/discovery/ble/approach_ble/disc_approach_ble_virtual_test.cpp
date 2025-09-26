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

#include <gtest/gtest.h>

#include "disc_approach_ble.h"
#include "disc_approach_ble_virtual.c"
#include "disc_log.h"
#include "softbus_error_code.h"

using namespace testing::ext;

constexpr uint32_t APPROACH_CAPABILITY = 1U << APPROACH_CAPABILITY_BITMAP;

const std::string CAPABILITY_DATA = R"({"business":{"prompt":0,"cmd":2},"modelId":"ABCDEF","subModelId":"DD",)"
                                    R"("lBatt":{"charging":1,"lvl":90},"seq":0,"advPower":-38})";

namespace OHOS {
class DiscApproachBleVirtualTest : public testing::Test {
public:
    DiscApproachBleVirtualTest() { }
    ~DiscApproachBleVirtualTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void DiscApproachBleVirtualTest::SetUpTestCase(void) { }

void DiscApproachBleVirtualTest::TearDownTestCase(void) { }

/*
 * @tc.name: DiscApproachBleInitTest001
 * @tc.desc: test DiscApproachBleInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, DiscApproachBleInitTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscApproachBleInitTest001 begin");

    DiscoveryBleDispatcherInterface *dispatcherInterface = DiscApproachBleInit(nullptr);
    EXPECT_NE(dispatcherInterface, nullptr);

    DiscInnerCallback discInnerCallback = {
        .OnDeviceFound = nullptr,
    };
    dispatcherInterface = DiscApproachBleInit(&discInnerCallback);
    EXPECT_NE(dispatcherInterface, nullptr);

    int32_t ret = DiscApproachBleEventInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscApproachBleDeinit();
    DiscApproachBleEventDeinit();

    DISC_LOGI(DISC_TEST, "DiscApproachBleInitTest001 end");
}

/*
 * @tc.name: DiscApproachBleInitTest002
 * @tc.desc: test DiscApproachBleInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, DiscApproachBleInitTest002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscApproachBleInitTest002 begin");

    DiscoveryBleDispatcherInterface *dispatcherInterface = nullptr;
    DiscInnerCallback discInnerCallback = {
        .OnDeviceFound = nullptr,
    };
    dispatcherInterface = DiscApproachBleInit(&discInnerCallback);

    EXPECT_NE(dispatcherInterface, nullptr);
    EXPECT_NE(dispatcherInterface->IsConcern, nullptr);
    EXPECT_NE(dispatcherInterface->mediumInterface, nullptr);

    EXPECT_NE(dispatcherInterface->mediumInterface->Publish, nullptr);
    EXPECT_NE(dispatcherInterface->mediumInterface->Unpublish, nullptr);
    EXPECT_NE(dispatcherInterface->mediumInterface->StartScan, nullptr);
    EXPECT_NE(dispatcherInterface->mediumInterface->StopScan, nullptr);

    EXPECT_NE(dispatcherInterface->mediumInterface->StartAdvertise, nullptr);
    EXPECT_NE(dispatcherInterface->mediumInterface->StopAdvertise, nullptr);
    EXPECT_NE(dispatcherInterface->mediumInterface->Subscribe, nullptr);
    EXPECT_NE(dispatcherInterface->mediumInterface->Unsubscribe, nullptr);

    EXPECT_NE(dispatcherInterface->mediumInterface->LinkStatusChanged, nullptr);
    EXPECT_NE(dispatcherInterface->mediumInterface->UpdateLocalDeviceInfo, nullptr);

    DISC_LOGI(DISC_TEST, "DiscApproachBleInitTest002 end");
}

/*
 * @tc.name: ApproachBleIsConcernTest001
 * @tc.desc: test ApproachBleIsConcern
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, ApproachBleIsConcernTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ApproachBleIsConcernTest001 begin");

    DiscoveryBleDispatcherInterface *dispatcherInterface = nullptr;
    DiscInnerCallback discInnerCallback = {
        .OnDeviceFound = nullptr,
    };
    dispatcherInterface = DiscApproachBleInit(&discInnerCallback);
    EXPECT_NE(dispatcherInterface, nullptr);

    EXPECT_FALSE(dispatcherInterface->IsConcern(APPROACH_CAPABILITY));

    uint32_t castPlusCapability = 1U << 3;
    EXPECT_FALSE(dispatcherInterface->IsConcern(castPlusCapability));

    uint32_t ddmpCapability = 1U << 6;
    EXPECT_FALSE(dispatcherInterface->IsConcern(ddmpCapability));

    uint32_t osdCapability = 1U << 7;
    EXPECT_FALSE(dispatcherInterface->IsConcern(osdCapability));

    uint32_t shareCapability = 1U << 8;
    EXPECT_FALSE(dispatcherInterface->IsConcern(shareCapability));

    DISC_LOGI(DISC_TEST, "ApproachBleIsConcernTest001 end");
}

/*
 * @tc.name: CalledNotSupportFunctionReturnNotImplement001
 * @tc.desc: should return not implement when called active refresh or passive publish
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, CalledNotSupportFunctionReturnNotImplement001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "CalledNotSupportFunctionReturnNotImplement001 begin");

    DiscoveryBleDispatcherInterface *dispatcherInterface = nullptr;
    DiscInnerCallback discInnerCallback = {
        .OnDeviceFound = nullptr,
    };
    dispatcherInterface = DiscApproachBleInit(&discInnerCallback);
    EXPECT_NE(dispatcherInterface, nullptr);

    EXPECT_EQ(dispatcherInterface->mediumInterface->Publish(nullptr), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->StartScan(nullptr), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->Unpublish(nullptr), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->StopScan(nullptr), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->StartAdvertise(nullptr), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->Subscribe(nullptr), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->Unsubscribe(nullptr), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->StopAdvertise(nullptr), SOFTBUS_NOT_IMPLEMENT);

    dispatcherInterface->mediumInterface->LinkStatusChanged(LINK_STATUS_UP, 0);
    dispatcherInterface->mediumInterface->UpdateLocalDeviceInfo(TYPE_LOCAL_DEVICE_NAME);

    DISC_LOGI(DISC_TEST, "CalledNotSupportFunctionReturnNotImplement001 end");
}

/*
 * @tc.name: CalledNotSupportFunctionReturnNotImplement002
 * @tc.desc: should return not implement when called active refresh or passive publish
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, CalledNotSupportFunctionReturnNotImplement002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "CalledNotSupportFunctionReturnNotImplement002 begin");

    DiscoveryBleDispatcherInterface *dispatcherInterface = nullptr;
    DiscInnerCallback discInnerCallback = {
        .OnDeviceFound = nullptr,
    };
    dispatcherInterface = DiscApproachBleInit(&discInnerCallback);
    EXPECT_NE(dispatcherInterface, nullptr);

    PublishOption publishOption = {
        .capabilityData = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(CAPABILITY_DATA.c_str())),
        .dataLen = CAPABILITY_DATA.length(),
    };

    const SubscribeOption subscribeOption = {
        .freq = MID,
    };

    EXPECT_EQ(dispatcherInterface->mediumInterface->Publish(&publishOption), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->StartScan(&publishOption), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->Unpublish(&publishOption), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->StopScan(&publishOption), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->StartAdvertise(&subscribeOption), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->Subscribe(&subscribeOption), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->Unsubscribe(&subscribeOption), SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(dispatcherInterface->mediumInterface->StopAdvertise(&subscribeOption), SOFTBUS_NOT_IMPLEMENT);

    DISC_LOGI(DISC_TEST, "CalledNotSupportFunctionReturnNotImplement002 end");
}

/*
 * @tc.name: ApproachBleStartActivePublishTest001
 * @tc.desc: test ApproachBleStartActivePublish
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, ApproachBleStartActivePublishTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ApproachBleStartActivePublishTest001 begin");

    PublishOption publishOption = {
        .capabilityData = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(CAPABILITY_DATA.c_str())),
        .dataLen = CAPABILITY_DATA.length(),
    };

    int32_t ret = ApproachBleStartActivePublish(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = ApproachBleStartActivePublish(&publishOption);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    DISC_LOGI(DISC_TEST, "ApproachBleStartActivePublishTest001 end");
}

/*
 * @tc.name: ApproachBleStartPassivePublishTest001
 * @tc.desc: test ApproachBleStartPassivePublish
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, ApproachBleStartPassivePublishTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ApproachBleStartPassivePublishTest001 begin");

    PublishOption publishOption = {
        .capabilityData = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(CAPABILITY_DATA.c_str())),
        .dataLen = CAPABILITY_DATA.length(),
    };

    int32_t ret = ApproachBleStartPassivePublish(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = ApproachBleStartPassivePublish(&publishOption);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    DISC_LOGI(DISC_TEST, "ApproachBleStartPassivePublishTest001 end");
}

/*
 * @tc.name: ApproachBleStopActivePublishTest001
 * @tc.desc: test ApproachBleStopActivePublish
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, ApproachBleStopActivePublishTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ApproachBleStopActivePublishTest001 begin");

    PublishOption publishOption = {
        .capabilityData = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(CAPABILITY_DATA.c_str())),
        .dataLen = CAPABILITY_DATA.length(),
    };

    int32_t ret = ApproachBleStopActivePublish(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = ApproachBleStopActivePublish(&publishOption);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    DISC_LOGI(DISC_TEST, "ApproachBleStopActivePublishTest001 end");
}

/*
 * @tc.name: ApproachBleStopPassivePublishTest001
 * @tc.desc: test ApproachBleStopPassivePublish
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, ApproachBleStopPassivePublishTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ApproachBleStopPassivePublishTest001 begin");

    PublishOption publishOption = {
        .capabilityData = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(CAPABILITY_DATA.c_str())),
        .dataLen = CAPABILITY_DATA.length(),
    };

    int32_t ret = ApproachBleStopPassivePublish(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = ApproachBleStopPassivePublish(&publishOption);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    DISC_LOGI(DISC_TEST, "ApproachBleStopPassivePublishTest001 end");
}

/*
 * @tc.name: ApproachBleStartActiveDiscoveryTest001
 * @tc.desc: test ApproachBleStartActiveDiscovery
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, ApproachBleStartActiveDiscoveryTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ApproachBleStartActiveDiscoveryTest001 begin");

    const SubscribeOption subscribeOption = {
        .freq = MID,
    };

    int32_t ret = ApproachBleStartActiveDiscovery(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = ApproachBleStartActiveDiscovery(&subscribeOption);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    DISC_LOGI(DISC_TEST, "ApproachBleStartActiveDiscoveryTest001 end");
}

/*
 * @tc.name: ApproachBleStartPassiveDiscoveryTest001
 * @tc.desc: test ApproachBleStartPassiveDiscovery
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, ApproachBleStartPassiveDiscoveryTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ApproachBleStartPassiveDiscoveryTest001 begin");

    const SubscribeOption subscribeOption = {
        .freq = MID,
    };

    int32_t ret = ApproachBleStartPassiveDiscovery(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = ApproachBleStartPassiveDiscovery(&subscribeOption);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    DISC_LOGI(DISC_TEST, "ApproachBleStartPassiveDiscoveryTest001 end");
}

/*
 * @tc.name: ApproachBleStopPassiveDiscoveryTest001
 * @tc.desc: test ApproachBleStopPassiveDiscovery
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, ApproachBleStopPassiveDiscoveryTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ApproachBleStopPassiveDiscoveryTest001 begin");

    const SubscribeOption subscribeOption = {
        .freq = MID,
    };

    int32_t ret = ApproachBleStopPassiveDiscovery(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = ApproachBleStopPassiveDiscovery(&subscribeOption);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    DISC_LOGI(DISC_TEST, "ApproachBleStopPassiveDiscoveryTest001 end");
}

/*
 * @tc.name: ApproachBleStopActiveDiscoveryTest001
 * @tc.desc: test ApproachBleStopActiveDiscovery
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscApproachBleVirtualTest, ApproachBleStopActiveDiscoveryTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ApproachBleStopActiveDiscoveryTest001 begin");

    const SubscribeOption subscribeOption = {
        .freq = MID,
    };

    int32_t ret = ApproachBleStopActiveDiscovery(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = ApproachBleStopActiveDiscovery(&subscribeOption);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    DISC_LOGI(DISC_TEST, "ApproachBleStopActiveDiscoveryTest001 end");
}
} // namespace OHOS
