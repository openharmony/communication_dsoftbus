/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <unistd.h>

#include "disc_ble_dispatcher.h"
#include "disc_interface.h"
#include "disc_log.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {
typedef struct {
    int32_t publishCntA;
    int32_t startScanCntA;
    int32_t unpublishCntA;
    int32_t stopScanCntA;
    int32_t startAdvertiseCntA;
    int32_t subscribeCntA;
    int32_t unsubscribeCntA;
    int32_t stopAdvertiseCntA;
    int32_t linkStatusChangedCntA;
    int32_t updateLocalDeviceInfoCntA;
} InterfaceFunCntA;

typedef struct {
    int32_t publishCntB;
    int32_t startScanCntB;
    int32_t unpublishCntB;
    int32_t stopScanCntB;
    int32_t startAdvertiseCntB;
    int32_t subscribeCntB;
    int32_t stopAdvertiseCntB;
    int32_t unsubscribeCntB;
} InterfaceFunCntB;

#define IS_CONCERNA 1
#define IS_CONCERNB 2
InterfaceFunCntA g_interfaceFunCntA = { .publishCntA = 0,
    .startScanCntA = 0,
    .unpublishCntA = 0,
    .stopScanCntA = 0,
    .startAdvertiseCntA = 0,
    .subscribeCntA = 0,
    .unsubscribeCntA = 0,
    .stopAdvertiseCntA = 0,
    .linkStatusChangedCntA = 0,
    .updateLocalDeviceInfoCntA = 0 };

InterfaceFunCntB g_interfaceFunCntB = {
    .publishCntB = 0,
    .startScanCntB = 0,
    .unpublishCntB = 0,
    .stopScanCntB = 0,
    .startAdvertiseCntB = 0,
    .subscribeCntB = 0,
    .stopAdvertiseCntB = 0,
    .unsubscribeCntB = 0,
};
static bool IsConcernA(uint32_t capability)
{
    if (capability == IS_CONCERNA) {
        return true;
    }
    return false;
}

static bool IsConcernB(uint32_t capability)
{
    if (capability == IS_CONCERNB) {
        return true;
    }
    return false;
}

static int32_t PublishA(const PublishOption *option)
{
    if (IsConcernA(option->capabilityBitmap[0])) {
        g_interfaceFunCntA.publishCntA = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t StartScanA(const PublishOption *option)
{
    if (IsConcernA(option->capabilityBitmap[0])) {
        g_interfaceFunCntA.startScanCntA = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t UnpublishA(const PublishOption *option)
{
    if (IsConcernA(option->capabilityBitmap[0])) {
        g_interfaceFunCntA.unpublishCntA = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t StopScanA(const PublishOption *option)
{
    if (IsConcernA(option->capabilityBitmap[0])) {
        g_interfaceFunCntA.stopScanCntA = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t StartAdvertiseA(const SubscribeOption *option)
{
    if (IsConcernA(option->capabilityBitmap[0])) {
        g_interfaceFunCntA.startAdvertiseCntA = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t SubscribeA(const SubscribeOption *option)
{
    if (IsConcernA(option->capabilityBitmap[0])) {
        g_interfaceFunCntA.subscribeCntA = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t UnsubscribeA(const SubscribeOption *option)
{
    if (IsConcernA(option->capabilityBitmap[0])) {
        g_interfaceFunCntA.unsubscribeCntA = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t StopAdvertiseA(const SubscribeOption *option)
{
    if (IsConcernA(option->capabilityBitmap[0])) {
        g_interfaceFunCntA.stopAdvertiseCntA = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static void LinkStatusChangedA(LinkStatus status)
{
    g_interfaceFunCntA.linkStatusChangedCntA = 1;
}

static void UpdateLocalDeviceInfoA(InfoTypeChanged type)
{
    (void)type;
    g_interfaceFunCntA.updateLocalDeviceInfoCntA = 1;
}

static int32_t PublishB(const PublishOption *option)
{
    if (IsConcernB(option->capabilityBitmap[0])) {
        g_interfaceFunCntB.publishCntB = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t StartScanB(const PublishOption *option)
{
    if (IsConcernB(option->capabilityBitmap[0])) {
        g_interfaceFunCntB.startScanCntB = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t UnpublishB(const PublishOption *option)
{
    if (IsConcernB(option->capabilityBitmap[0])) {
        g_interfaceFunCntB.unpublishCntB = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t StopScanB(const PublishOption *option)
{
    if (IsConcernB(option->capabilityBitmap[0])) {
        g_interfaceFunCntB.stopScanCntB = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t StartAdvertiseB(const SubscribeOption *option)
{
    if (IsConcernB(option->capabilityBitmap[0])) {
        g_interfaceFunCntB.startAdvertiseCntB = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t SubscribeB(const SubscribeOption *option)
{
    if (IsConcernB(option->capabilityBitmap[0])) {
        g_interfaceFunCntB.subscribeCntB = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t UnsubscribeB(const SubscribeOption *option)
{
    if (IsConcernB(option->capabilityBitmap[0])) {
        g_interfaceFunCntB.unsubscribeCntB = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static int32_t StopAdvertiseB(const SubscribeOption *option)
{
    if (IsConcernB(option->capabilityBitmap[0])) {
        g_interfaceFunCntB.stopAdvertiseCntB = 1;
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
}

static PublishOption g_pOption0 = {
    .freq = 1,
    .capabilityBitmap = {0},
    .capabilityData = nullptr,
    .dataLen = 0,
    .ranging = true
};

static SubscribeOption g_sOption0 = { .freq = 1,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capabilityBitmap = { 0 },
    .capabilityData = nullptr,
    .dataLen = 0 };

static PublishOption g_pOption1 = {
    .freq = 1,
    .capabilityBitmap = {1},
    .capabilityData = NULL,
    .dataLen = 0,
    .ranging = true
};

static SubscribeOption g_sOption1 = { .freq = 1,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capabilityBitmap = { 1 },
    .capabilityData = NULL,
    .dataLen = 0 };

static PublishOption g_pOption2 = {
    .freq = 1,
    .capabilityBitmap = {2},
    .capabilityData = NULL,
    .dataLen = 0,
    .ranging = true
};

static SubscribeOption g_sOption2 = { .freq = 1,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capabilityBitmap = { 2 },
    .capabilityData = NULL,
    .dataLen = 0 };

static PublishOption g_pOption3 = {
    .freq = 1,
    .capabilityBitmap = {3},
    .capabilityData = NULL,
    .dataLen = 0,
    .ranging = true
};

static SubscribeOption g_sOption3 = { .freq = 1,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capabilityBitmap = { 3 },
    .capabilityData = NULL,
    .dataLen = 0 };

class DiscBleDispatcherTest : public testing::Test {
public:
    DiscBleDispatcherTest() { }
    ~DiscBleDispatcherTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

static DiscoveryFuncInterface g_discoveryFuncA = {
    .Publish = PublishA,
    .StartScan = StartScanA,
    .Unpublish = UnpublishA,
    .StopScan = StopScanA,
    .StartAdvertise = StartAdvertiseA,
    .Subscribe = SubscribeA,
    .Unsubscribe = UnsubscribeA,
    .StopAdvertise = StopAdvertiseA,
    .LinkStatusChanged = LinkStatusChangedA,
    .UpdateLocalDeviceInfo = UpdateLocalDeviceInfoA,
};

static DiscoveryBleDispatcherInterface g_interfaceA = {
    .IsConcern = IsConcernA,
    .mediumInterface = &g_discoveryFuncA,
};

static DiscoveryFuncInterface g_discoveryFuncB = {
    .Publish = PublishB,
    .StartScan = StartScanB,
    .Unpublish = UnpublishB,
    .StopScan = StopScanB,
    .StartAdvertise = StartAdvertiseB,
    .Subscribe = SubscribeB,
    .Unsubscribe = UnsubscribeB,
    .StopAdvertise = StopAdvertiseB,
    .LinkStatusChanged = LinkStatusChangedA,
    .UpdateLocalDeviceInfo = UpdateLocalDeviceInfoA,
};

static DiscoveryBleDispatcherInterface g_interfaceB = {
    .IsConcern = IsConcernB,
    .mediumInterface = &g_discoveryFuncB,
};

void DiscBleDispatcherTest::SetUpTestCase(void) { }

void DiscBleDispatcherTest::TearDownTestCase(void) { }

void DiscBleDispatcherTest::SetUp(void) { }

void DiscBleDispatcherTest::TearDown(void) { }

/*
 * @tc.name: testDiscPublish001
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, testDiscPublish001, TestSize.Level1)
{
    printf("testDiscPublish001\r\n");
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t ret;
    int32_t beforeFunCntA;
    int32_t beforeFunCntB;
    int32_t afterFunCntA;
    int32_t afterFunCntB;

    beforeFunCntA = g_interfaceFunCntA.publishCntA;
    beforeFunCntB = g_interfaceFunCntB.publishCntB;
    ret = interface->Publish(&g_pOption1);
    afterFunCntA = g_interfaceFunCntA.publishCntA;
    afterFunCntB = g_interfaceFunCntB.publishCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.startScanCntA;
    beforeFunCntB = g_interfaceFunCntB.startScanCntB;
    ret = interface->StartScan(&g_pOption1);
    afterFunCntA = g_interfaceFunCntA.startScanCntA;
    afterFunCntB = g_interfaceFunCntB.startScanCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.unpublishCntA;
    beforeFunCntB = g_interfaceFunCntB.unpublishCntB;
    ret = interface->Unpublish(&g_pOption1);
    afterFunCntA = g_interfaceFunCntA.unpublishCntA;
    afterFunCntB = g_interfaceFunCntB.unpublishCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.stopScanCntA;
    beforeFunCntB = g_interfaceFunCntB.stopScanCntB;
    ret = interface->StopScan(&g_pOption1);
    afterFunCntA = g_interfaceFunCntA.stopScanCntA;
    afterFunCntB = g_interfaceFunCntB.stopScanCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);
};

/*
 * @tc.name: testDiscovery001
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, testDiscovery001, TestSize.Level1)
{
    printf("testDiscovery001\r\n");
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t ret;
    int32_t beforeFunCntA;
    int32_t beforeFunCntB;
    int32_t afterFunCntA;
    int32_t afterFunCntB;

    beforeFunCntA = g_interfaceFunCntA.startAdvertiseCntA;
    beforeFunCntB = g_interfaceFunCntB.startAdvertiseCntB;
    ret = interface->StartAdvertise(&g_sOption1);
    afterFunCntA = g_interfaceFunCntA.startAdvertiseCntA;
    afterFunCntB = g_interfaceFunCntB.startAdvertiseCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.subscribeCntA;
    beforeFunCntB = g_interfaceFunCntB.subscribeCntB;
    ret = interface->Subscribe(&g_sOption1);
    afterFunCntA = g_interfaceFunCntA.subscribeCntA;
    afterFunCntB = g_interfaceFunCntB.subscribeCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.unsubscribeCntA;
    beforeFunCntB = g_interfaceFunCntB.unsubscribeCntB;
    ret = interface->Unsubscribe(&g_sOption1);
    afterFunCntA = g_interfaceFunCntA.unsubscribeCntA;
    afterFunCntB = g_interfaceFunCntB.unsubscribeCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.stopAdvertiseCntA;
    beforeFunCntB = g_interfaceFunCntB.stopAdvertiseCntB;
    ret = interface->StopAdvertise(&g_sOption1);
    afterFunCntA = g_interfaceFunCntA.stopAdvertiseCntA;
    afterFunCntB = g_interfaceFunCntB.stopAdvertiseCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);
};

/*
 * @tc.name: testDiscPublish002
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, testDiscPublish002, TestSize.Level1)
{
    printf("testDiscPublish002\r\n");
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t ret;
    int32_t beforeFunCntA;
    int32_t beforeFunCntB;
    int32_t afterFunCntA;
    int32_t afterFunCntB;

    beforeFunCntA = g_interfaceFunCntA.publishCntA;
    beforeFunCntB = g_interfaceFunCntB.publishCntB;
    ret = interface->Publish(&g_pOption2);
    afterFunCntA = g_interfaceFunCntA.publishCntA;
    afterFunCntB = g_interfaceFunCntB.publishCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.startScanCntA;
    beforeFunCntB = g_interfaceFunCntB.startScanCntB;
    ret = interface->StartScan(&g_pOption2);
    afterFunCntA = g_interfaceFunCntA.startScanCntA;
    afterFunCntB = g_interfaceFunCntB.startScanCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.unpublishCntA;
    beforeFunCntB = g_interfaceFunCntB.unpublishCntB;
    ret = interface->Unpublish(&g_pOption2);
    afterFunCntA = g_interfaceFunCntA.unpublishCntA;
    afterFunCntB = g_interfaceFunCntB.unpublishCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.stopScanCntA;
    beforeFunCntB = g_interfaceFunCntB.stopScanCntB;
    ret = interface->StopScan(&g_pOption2);
    afterFunCntA = g_interfaceFunCntA.stopScanCntA;
    afterFunCntB = g_interfaceFunCntB.stopScanCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
};

/*
 * @tc.name: testDiscovery002
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, testDiscovery002, TestSize.Level1)
{
    printf("testDiscovery002\r\n");
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t ret;
    int32_t beforeFunCntA;
    int32_t beforeFunCntB;
    int32_t afterFunCntA;
    int32_t afterFunCntB;

    beforeFunCntA = g_interfaceFunCntA.startAdvertiseCntA;
    beforeFunCntB = g_interfaceFunCntB.startAdvertiseCntB;
    ret = interface->StartAdvertise(&g_sOption2);
    afterFunCntA = g_interfaceFunCntA.startAdvertiseCntA;
    afterFunCntB = g_interfaceFunCntB.startAdvertiseCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.subscribeCntA;
    beforeFunCntB = g_interfaceFunCntB.subscribeCntB;
    ret = interface->Subscribe(&g_sOption2);
    afterFunCntA = g_interfaceFunCntA.subscribeCntA;
    afterFunCntB = g_interfaceFunCntB.subscribeCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.unsubscribeCntA;
    beforeFunCntB = g_interfaceFunCntB.unsubscribeCntB;
    ret = interface->Unsubscribe(&g_sOption2);
    afterFunCntA = g_interfaceFunCntA.unsubscribeCntA;
    afterFunCntB = g_interfaceFunCntB.unsubscribeCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.stopAdvertiseCntA;
    beforeFunCntB = g_interfaceFunCntB.stopAdvertiseCntB;
    ret = interface->StopAdvertise(&g_sOption2);
    afterFunCntA = g_interfaceFunCntA.stopAdvertiseCntA;
    afterFunCntB = g_interfaceFunCntB.stopAdvertiseCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
};

/*
 * @tc.name: testDiscPublish003
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, testDiscPublish003, TestSize.Level1)
{
    printf("testDiscDispatcher003\r\n");
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t ret;
    int32_t beforeFunCntA;
    int32_t beforeFunCntB;
    int32_t afterFunCntA;
    int32_t afterFunCntB;

    beforeFunCntA = g_interfaceFunCntA.publishCntA;
    beforeFunCntB = g_interfaceFunCntB.publishCntB;
    ret = interface->Publish(&g_pOption3);
    afterFunCntA = g_interfaceFunCntA.publishCntA;
    afterFunCntB = g_interfaceFunCntB.publishCntB;
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.startScanCntA;
    beforeFunCntB = g_interfaceFunCntB.startScanCntB;
    ret = interface->StartScan(&g_pOption3);
    afterFunCntA = g_interfaceFunCntA.startScanCntA;
    afterFunCntB = g_interfaceFunCntB.startScanCntB;
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.unpublishCntA;
    beforeFunCntB = g_interfaceFunCntB.unpublishCntB;
    ret = interface->Unpublish(&g_pOption3);
    afterFunCntA = g_interfaceFunCntA.unpublishCntA;
    afterFunCntB = g_interfaceFunCntB.unpublishCntB;
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.stopScanCntA;
    beforeFunCntB = g_interfaceFunCntB.stopScanCntB;
    ret = interface->StopScan(&g_pOption3);
    afterFunCntA = g_interfaceFunCntA.stopScanCntA;
    afterFunCntB = g_interfaceFunCntB.stopScanCntB;
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);
};

/*
 * @tc.name: testDiscovery003
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, testDiscovery003, TestSize.Level1)
{
    printf("testDiscovery003\r\n");
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t ret;
    int32_t beforeFunCntA;
    int32_t beforeFunCntB;
    int32_t afterFunCntA;
    int32_t afterFunCntB;

    beforeFunCntA = g_interfaceFunCntA.startAdvertiseCntA;
    beforeFunCntB = g_interfaceFunCntB.startAdvertiseCntB;
    ret = interface->StartAdvertise(&g_sOption3);
    afterFunCntA = g_interfaceFunCntA.startAdvertiseCntA;
    afterFunCntB = g_interfaceFunCntB.startAdvertiseCntB;
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.subscribeCntA;
    beforeFunCntB = g_interfaceFunCntB.subscribeCntB;
    ret = interface->Subscribe(&g_sOption3);
    afterFunCntA = g_interfaceFunCntA.subscribeCntA;
    afterFunCntB = g_interfaceFunCntB.subscribeCntB;
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.unsubscribeCntA;
    beforeFunCntB = g_interfaceFunCntB.unsubscribeCntB;
    ret = interface->Unsubscribe(&g_sOption3);
    afterFunCntA = g_interfaceFunCntA.unsubscribeCntA;
    afterFunCntB = g_interfaceFunCntB.unsubscribeCntB;
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);

    beforeFunCntA = g_interfaceFunCntA.stopAdvertiseCntA;
    beforeFunCntB = g_interfaceFunCntB.stopAdvertiseCntB;
    ret = interface->StopAdvertise(&g_sOption3);
    afterFunCntA = g_interfaceFunCntA.stopAdvertiseCntA;
    afterFunCntB = g_interfaceFunCntB.stopAdvertiseCntB;
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA, afterFunCntA);
    EXPECT_EQ(beforeFunCntB, afterFunCntB);
};

/*
 * @tc.name: testLinkStatusChanged001
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, testLinkStatusChanged001, TestSize.Level1)
{
    printf("testLinkStatusChanged001\r\n");
    static LinkStatus status = LINK_STATUS_UP;
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t beforeFunCntA;
    int32_t afterFunCntA;
    beforeFunCntA = g_interfaceFunCntA.linkStatusChangedCntA;
    interface->LinkStatusChanged(status);
    afterFunCntA = g_interfaceFunCntA.linkStatusChangedCntA;
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
};

/*
 * @tc.name: testUpdateLocalDeviceInfo001
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, testUpdateLocalDeviceInfo001, TestSize.Level1)
{
    printf("testUpdateLocalDeviceInfo001\r\n");
    static InfoTypeChanged type = TYPE_LOCAL_DEVICE_NAME;
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t beforeFunCntA;
    int32_t afterFunCntA;
    beforeFunCntA = g_interfaceFunCntA.updateLocalDeviceInfoCntA;
    interface->UpdateLocalDeviceInfo(type);
    afterFunCntA = g_interfaceFunCntA.updateLocalDeviceInfoCntA;
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
}

/*
 * @tc.name: BleDispatchPublishOption001
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchPublishOption001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchPublishOption001");
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t ret = interface->Publish(&g_pOption0);
    EXPECT_EQ(SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL, ret);
}

/*
 * @tc.name: BleDispatchSubscribeOption001
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchSubscribeOption001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchSubscribeOption001");
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t ret = interface->StartAdvertise(&g_sOption0);
    EXPECT_EQ(SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL, ret);
}

/*
 * @tc.name: DiscBleInit001
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, DiscBleInit001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleInit001");
    DiscoveryFuncInterface *interface = DiscBleInit(nullptr);
    EXPECT_EQ(interface, nullptr);
}

/*
 * @tc.name: DiscBleInit002
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, DiscBleInit002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleInit002");
    DiscInnerCallback g_discMgrMediumCb;
    g_discMgrMediumCb.OnDeviceFound = nullptr;
    DiscoveryFuncInterface *interface = DiscBleInit(&g_discMgrMediumCb);
    EXPECT_EQ(interface, nullptr);
}
} // namespace OHOS