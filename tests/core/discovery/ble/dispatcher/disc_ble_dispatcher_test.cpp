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
    int32_t linkStatusChangedCntB;
    int32_t updateLocalDeviceInfoCntB;
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
    .linkStatusChangedCntB = 0,
    .updateLocalDeviceInfoCntB = 0,
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

static void LinkStatusChangedA(LinkStatus status, int32_t ifnameIdx)
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

static void LinkStatusChangedB(LinkStatus status, int32_t ifnameIdx)
{
    g_interfaceFunCntB.linkStatusChangedCntB = 1;
}

static void UpdateLocalDeviceInfoB(InfoTypeChanged type)
{
    (void)type;
    g_interfaceFunCntB.updateLocalDeviceInfoCntB = 1;
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
    .capabilityData = nullptr,
    .dataLen = 0,
    .ranging = true
};

static SubscribeOption g_sOption1 = { .freq = 1,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capabilityBitmap = { 1 },
    .capabilityData = nullptr,
    .dataLen = 0 };

static PublishOption g_pOption2 = {
    .freq = 1,
    .capabilityBitmap = {2},
    .capabilityData = nullptr,
    .dataLen = 0,
    .ranging = true
};

static SubscribeOption g_sOption2 = { .freq = 1,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capabilityBitmap = { 2 },
    .capabilityData = nullptr,
    .dataLen = 0
};

static PublishOption g_pOption3 = {
    .freq = 1,
    .capabilityBitmap = {3},
    .capabilityData = nullptr,
    .dataLen = 0,
    .ranging = true
};

static SubscribeOption g_sOption3 = { .freq = 1,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capabilityBitmap = { 3 },
    .capabilityData = nullptr,
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
    .LinkStatusChanged = LinkStatusChangedB,
    .UpdateLocalDeviceInfo = UpdateLocalDeviceInfoB,
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
 * @tc.name: DiscPublish001
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, DiscPublish001, TestSize.Level1)
{
    printf("DiscPublish001\r\n");
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
 * @tc.name: Discovery001
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, Discovery001, TestSize.Level1)
{
    printf("Discovery001\r\n");
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
 * @tc.name: DiscPublish002
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, DiscPublish002, TestSize.Level1)
{
    printf("DiscPublish002\r\n");
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
 * @tc.name: Discovery002
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, Discovery002, TestSize.Level1)
{
    printf("Discovery002\r\n");
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
 * @tc.name: DiscPublish003
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, DiscPublish003, TestSize.Level1)
{
    printf("DiscDispatcher003\r\n");
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
 * @tc.name: Discovery003
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, Discovery003, TestSize.Level1)
{
    printf("Discovery003\r\n");
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
 * @tc.name: LinkStatusChanged001
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, LinkStatusChanged001, TestSize.Level1)
{
    printf("LinkStatusChanged001\r\n");
    static LinkStatus status = LINK_STATUS_UP;
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t beforeFunCntA;
    int32_t afterFunCntA;
    beforeFunCntA = g_interfaceFunCntA.linkStatusChangedCntA;
    interface->LinkStatusChanged(status, 0);
    afterFunCntA = g_interfaceFunCntA.linkStatusChangedCntA;
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
};

/*
 * @tc.name: UpdateLocalDeviceInfo001
 * @tc.desc: test dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, UpdateLocalDeviceInfo001, TestSize.Level1)
{
    printf("UpdateLocalDeviceInfo001\r\n");
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

/*
 * @tc.name: FindDiscoveryFuncInterfaceNullDispatcher001
 * @tc.desc: test FindDiscoveryFuncInterface with null dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, FindDiscoveryFuncInterfaceNullDispatcher001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "FindDiscoveryFuncInterfaceNullDispatcher001");
    DiscoveryBleDispatcherInterface nullInterface = {0};
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &nullInterface);
    int32_t ret = interface->Publish(&g_pOption2);
    EXPECT_EQ(SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL, ret);
}

/*
 * @tc.name: BleDispatchSubscribeOptionNullInterface001
 * @tc.desc: test BleDispatchSubscribeOption with null interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchSubscribeOptionNullInterface001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchSubscribeOptionNullInterface001");
    DiscoveryBleDispatcherInterface interfaceWithNullMedium = {
        .IsConcern = IsConcernA,
        .mediumInterface = nullptr,
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&interfaceWithNullMedium, &g_interfaceB);
    int32_t ret = interface->StartAdvertise(&g_sOption1);
    EXPECT_EQ(SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL, ret);
}

/*
 * @tc.name: BleDispatchLinkStatusChangedNullDispatcher001
 * @tc.desc: test BleDispatchLinkStatusChanged with null dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchLinkStatusChangedNullDispatcher001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchLinkStatusChangedNullDispatcher001");
    g_interfaceFunCntB.linkStatusChangedCntB = 0;
    DiscoveryBleDispatcherInterface nullInterface = {0};
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&nullInterface, &g_interfaceB);
    static LinkStatus status = LINK_STATUS_UP;
    int32_t beforeFunCntB = g_interfaceFunCntB.linkStatusChangedCntB;
    interface->LinkStatusChanged(status, 0);
    int32_t afterFunCntB = g_interfaceFunCntB.linkStatusChangedCntB;
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
}

/*
 * @tc.name: BleDispatchLinkStatusChangedNullCallback001
 * @tc.desc: test BleDispatchLinkStatusChanged with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchLinkStatusChangedNullCallback001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchLinkStatusChangedNullCallback001");
    g_interfaceFunCntB.linkStatusChangedCntB = 0;
    DiscoveryFuncInterface nullCallbackInterface = {
        .Publish = nullptr,
        .StartScan = nullptr,
        .Unpublish = nullptr,
        .StopScan = nullptr,
        .StartAdvertise = nullptr,
        .Subscribe = nullptr,
        .Unsubscribe = nullptr,
        .StopAdvertise = nullptr,
        .LinkStatusChanged = nullptr,
        .UpdateLocalDeviceInfo = nullptr,
    };
    DiscoveryBleDispatcherInterface interfaceWithNullCallback = {
        .IsConcern = IsConcernA,
        .mediumInterface = &nullCallbackInterface,
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&interfaceWithNullCallback, &g_interfaceB);
    static LinkStatus status = LINK_STATUS_UP;
    int32_t beforeFunCntB = g_interfaceFunCntB.linkStatusChangedCntB;
    interface->LinkStatusChanged(status, 0);
    int32_t afterFunCntB = g_interfaceFunCntB.linkStatusChangedCntB;
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
}

/*
 * @tc.name: BleDispatchUpdateLocalDeviceInfoNullMediumInterface001
 * @tc.desc: test BleDispatchUpdateLocalDeviceInfo with null medium interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchUpdateLocalDeviceInfoNullMediumInterface001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchUpdateLocalDeviceInfoNullMediumInterface001");
    g_interfaceFunCntB.updateLocalDeviceInfoCntB = 0;
    DiscoveryBleDispatcherInterface interfaceWithNullMedium = {
        .IsConcern = IsConcernA,
        .mediumInterface = nullptr,
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&interfaceWithNullMedium, &g_interfaceB);
    static InfoTypeChanged type = TYPE_LOCAL_DEVICE_NAME;
    int32_t beforeFunCntB = g_interfaceFunCntB.updateLocalDeviceInfoCntB;
    interface->UpdateLocalDeviceInfo(type);
    int32_t afterFunCntB = g_interfaceFunCntB.updateLocalDeviceInfoCntB;
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
}

/*
 * @tc.name: BleDispatchUpdateLocalDeviceInfoNullCallback001
 * @tc.desc: test BleDispatchUpdateLocalDeviceInfo with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchUpdateLocalDeviceInfoNullCallback001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchUpdateLocalDeviceInfoNullCallback001");
    g_interfaceFunCntB.updateLocalDeviceInfoCntB = 0;
    DiscoveryFuncInterface nullCallbackInterface = {
        .Publish = nullptr,
        .StartScan = nullptr,
        .Unpublish = nullptr,
        .StopScan = nullptr,
        .StartAdvertise = nullptr,
        .Subscribe = nullptr,
        .Unsubscribe = nullptr,
        .StopAdvertise = nullptr,
        .LinkStatusChanged = nullptr,
        .UpdateLocalDeviceInfo = nullptr,
    };
    DiscoveryBleDispatcherInterface interfaceWithNullCallback = {
        .IsConcern = IsConcernA,
        .mediumInterface = &nullCallbackInterface,
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&interfaceWithNullCallback, &g_interfaceB);
    static InfoTypeChanged type = TYPE_LOCAL_DEVICE_NAME;
    int32_t beforeFunCntB = g_interfaceFunCntB.updateLocalDeviceInfoCntB;
    interface->UpdateLocalDeviceInfo(type);
    int32_t afterFunCntB = g_interfaceFunCntB.updateLocalDeviceInfoCntB;
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
}

/*
 * @tc.name: FindDiscoveryFuncInterfaceReturnNull001
 * @tc.desc: test FindDiscoveryFuncInterface return null for unsupported capability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, FindDiscoveryFuncInterfaceReturnNull001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "FindDiscoveryFuncInterfaceReturnNull001");
    PublishOption unsupportedOption = {
        .freq = 1,
        .capabilityBitmap = {99},
        .capabilityData = nullptr,
        .dataLen = 0,
        .ranging = true
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t ret = interface->Publish(&unsupportedOption);
    EXPECT_EQ(SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL, ret);
}

/*
 * @tc.name: BleDispatchPublishOptionPassiveMode001
 * @tc.desc: test BleDispatchPublishOption with passive mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchPublishOptionPassiveMode001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchPublishOptionPassiveMode001");
    g_interfaceFunCntA.startScanCntA = 0;
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t beforeFunCntA = g_interfaceFunCntA.startScanCntA;
    int32_t ret = interface->StartScan(&g_pOption1);
    int32_t afterFunCntA = g_interfaceFunCntA.startScanCntA;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
}

/*
 * @tc.name: BleDispatchUnpublishOptionPassiveMode001
 * @tc.desc: test BleDispatchUnpublishOption with passive mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchUnpublishOptionPassiveMode001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchUnpublishOptionPassiveMode001");
    g_interfaceFunCntA.stopScanCntA = 0;
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t beforeFunCntA = g_interfaceFunCntA.stopScanCntA;
    int32_t ret = interface->StopScan(&g_pOption1);
    int32_t afterFunCntA = g_interfaceFunCntA.stopScanCntA;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
}

/*
 * @tc.name: BleDispatchSubscribeOptionPassiveMode001
 * @tc.desc: test BleDispatchSubscribeOption with passive mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchSubscribeOptionPassiveMode001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchSubscribeOptionPassiveMode001");
    g_interfaceFunCntA.subscribeCntA = 0;
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t beforeFunCntA = g_interfaceFunCntA.subscribeCntA;
    int32_t ret = interface->Subscribe(&g_sOption1);
    int32_t afterFunCntA = g_interfaceFunCntA.subscribeCntA;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
}

/*
 * @tc.name: BleDispatchUnsubscribeOptionPassiveMode001
 * @tc.desc: test BleDispatchUnsubscribeOption with passive mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchUnsubscribeOptionPassiveMode001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchUnsubscribeOptionPassiveMode001");
    g_interfaceFunCntA.unsubscribeCntA = 0;
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t beforeFunCntA = g_interfaceFunCntA.unsubscribeCntA;
    int32_t ret = interface->Unsubscribe(&g_sOption1);
    int32_t afterFunCntA = g_interfaceFunCntA.unsubscribeCntA;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
}

/*
 * @tc.name: BleDispatchLinkStatusChangedWithNullDispatcher001
 * @tc.desc: test BleDispatchLinkStatusChanged with null dispatcher in array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchLinkStatusChangedWithNullDispatcher001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchLinkStatusChangedWithNullDispatcher001");
    g_interfaceFunCntB.linkStatusChangedCntB = 0;
    DiscoveryBleDispatcherInterface nullInterface = {0};
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&nullInterface, &g_interfaceB);
    static LinkStatus status = LINK_STATUS_UP;
    int32_t beforeFunCntB = g_interfaceFunCntB.linkStatusChangedCntB;
    interface->LinkStatusChanged(status, 0);
    int32_t afterFunCntB = g_interfaceFunCntB.linkStatusChangedCntB;
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
}

/*
 * @tc.name: BleDispatchPublishOptionNullInterface001
 * @tc.desc: test BleDispatchPublishOption with null interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchPublishOptionNullInterface001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchPublishOptionNullInterface001");
    DiscoveryBleDispatcherInterface interfaceWithNullMedium = {
        .IsConcern = IsConcernA,
        .mediumInterface = nullptr,
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&interfaceWithNullMedium, &g_interfaceB);
    int32_t ret = interface->Publish(&g_pOption1);
    EXPECT_EQ(SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL, ret);
}

/*
 * @tc.name: BleDispatchLinkStatusChangedNullMediumInterface001
 * @tc.desc: test BleDispatchLinkStatusChanged with null medium interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchLinkStatusChangedNullMediumInterface001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchLinkStatusChangedNullMediumInterface001");
    g_interfaceFunCntB.linkStatusChangedCntB = 0;
    DiscoveryBleDispatcherInterface interfaceWithNullMedium = {
        .IsConcern = IsConcernA,
        .mediumInterface = nullptr,
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&interfaceWithNullMedium, &g_interfaceB);
    static LinkStatus status = LINK_STATUS_UP;
    int32_t beforeFunCntB = g_interfaceFunCntB.linkStatusChangedCntB;
    interface->LinkStatusChanged(status, 0);
    int32_t afterFunCntB = g_interfaceFunCntB.linkStatusChangedCntB;
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
}

/*
 * @tc.name: BleDispatchUpdateLocalDeviceInfoNullDispatcher001
 * @tc.desc: test BleDispatchUpdateLocalDeviceInfo with null dispatcher
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchUpdateLocalDeviceInfoNullDispatcher001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchUpdateLocalDeviceInfoNullDispatcher001");
    g_interfaceFunCntB.updateLocalDeviceInfoCntB = 0;
    DiscoveryBleDispatcherInterface nullInterface = {0};
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&nullInterface, &g_interfaceB);
    static InfoTypeChanged type = TYPE_LOCAL_DEVICE_NAME;
    int32_t beforeFunCntB = g_interfaceFunCntB.updateLocalDeviceInfoCntB;
    interface->UpdateLocalDeviceInfo(type);
    int32_t afterFunCntB = g_interfaceFunCntB.updateLocalDeviceInfoCntB;
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
}

/*
 * @tc.name: BleDispatchPublishOptionPassiveModeWithInterfaceB001
 * @tc.desc: test BleDispatchPublishOption with passive mode and interface B
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchPublishOptionPassiveModeWithInterfaceB001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchPublishOptionPassiveModeWithInterfaceB001");
    g_interfaceFunCntB.startScanCntB = 0;
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t beforeFunCntB = g_interfaceFunCntB.startScanCntB;
    int32_t ret = interface->StartScan(&g_pOption2);
    int32_t afterFunCntB = g_interfaceFunCntB.startScanCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
}

/*
 * @tc.name: BleDispatchUnpublishOptionPassiveModeWithInterfaceB001
 * @tc.desc: test BleDispatchUnpublishOption with passive mode and interface B
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchUnpublishOptionPassiveModeWithInterfaceB001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchUnpublishOptionPassiveModeWithInterfaceB001");
    g_interfaceFunCntB.stopScanCntB = 0;
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t beforeFunCntB = g_interfaceFunCntB.stopScanCntB;
    int32_t ret = interface->StopScan(&g_pOption2);
    int32_t afterFunCntB = g_interfaceFunCntB.stopScanCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
}

/*
 * @tc.name: BleDispatchSubscribeOptionPassiveModeWithInterfaceB001
 * @tc.desc: test BleDispatchSubscribeOption with passive mode and interface B
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchSubscribeOptionPassiveModeWithInterfaceB001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchSubscribeOptionPassiveModeWithInterfaceB001");
    g_interfaceFunCntB.subscribeCntB = 0;
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t beforeFunCntB = g_interfaceFunCntB.subscribeCntB;
    int32_t ret = interface->Subscribe(&g_sOption2);
    int32_t afterFunCntB = g_interfaceFunCntB.subscribeCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
}

/*
 * @tc.name: BleDispatchUnsubscribeOptionPassiveModeWithInterfaceB001
 * @tc.desc: test BleDispatchUnsubscribeOption with passive mode and interface B
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchUnsubscribeOptionPassiveModeWithInterfaceB001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchUnsubscribeOptionPassiveModeWithInterfaceB001");
    g_interfaceFunCntB.unsubscribeCntB = 0;
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    int32_t beforeFunCntB = g_interfaceFunCntB.unsubscribeCntB;
    int32_t ret = interface->Unsubscribe(&g_sOption2);
    int32_t afterFunCntB = g_interfaceFunCntB.unsubscribeCntB;
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
}

/*
 * @tc.name: BleDispatchLinkStatusChangedWithBothInterfaces001
 * @tc.desc: test BleDispatchLinkStatusChanged with both interfaces
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchLinkStatusChangedWithBothInterfaces001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchLinkStatusChangedWithBothInterfaces001");
    g_interfaceFunCntA.linkStatusChangedCntA = 0;
    g_interfaceFunCntB.linkStatusChangedCntB = 0;
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&g_interfaceA, &g_interfaceB);
    static LinkStatus status = LINK_STATUS_DOWN;
    int32_t beforeFunCntA = g_interfaceFunCntA.linkStatusChangedCntA;
    int32_t beforeFunCntB = g_interfaceFunCntB.linkStatusChangedCntB;
    interface->LinkStatusChanged(status, 1);
    int32_t afterFunCntA = g_interfaceFunCntA.linkStatusChangedCntA;
    int32_t afterFunCntB = g_interfaceFunCntB.linkStatusChangedCntB;
    EXPECT_EQ(beforeFunCntA + 1, afterFunCntA);
    EXPECT_EQ(beforeFunCntB + 1, afterFunCntB);
}

/*
 * @tc.name: BleDispatchPublishOptionNullInterfaceForPassiveMode001
 * @tc.desc: test BleDispatchPublishOption with null interface for passive mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchPublishOptionNullInterfaceForPassiveMode001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchPublishOptionNullInterfaceForPassiveMode001");
    DiscoveryBleDispatcherInterface interfaceWithNullMedium = {
        .IsConcern = IsConcernA,
        .mediumInterface = nullptr,
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&interfaceWithNullMedium, &g_interfaceB);
    int32_t ret = interface->StartScan(&g_pOption1);
    EXPECT_EQ(SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL, ret);
}

/*
 * @tc.name: BleDispatchUnpublishOptionNullInterfaceForPassiveMode001
 * @tc.desc: test BleDispatchUnpublishOption with null interface for passive mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchUnpublishOptionNullInterfaceForPassiveMode001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchUnpublishOptionNullInterfaceForPassiveMode001");
    DiscoveryBleDispatcherInterface interfaceWithNullMedium = {
        .IsConcern = IsConcernA,
        .mediumInterface = nullptr,
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&interfaceWithNullMedium, &g_interfaceB);
    int32_t ret = interface->StopScan(&g_pOption1);
    EXPECT_EQ(SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL, ret);
}

/*
 * @tc.name: BleDispatchSubscribeOptionNullInterfaceForPassiveMode001
 * @tc.desc: test BleDispatchSubscribeOption with null interface for passive mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchSubscribeOptionNullInterfaceForPassiveMode001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchSubscribeOptionNullInterfaceForPassiveMode001");
    DiscoveryBleDispatcherInterface interfaceWithNullMedium = {
        .IsConcern = IsConcernA,
        .mediumInterface = nullptr,
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&interfaceWithNullMedium, &g_interfaceB);
    int32_t ret = interface->Subscribe(&g_sOption1);
    EXPECT_EQ(SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL, ret);
}

/*
 * @tc.name: BleDispatchUnsubscribeOptionNullInterfaceForPassiveMode001
 * @tc.desc: test BleDispatchUnsubscribeOption with null interface for passive mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchUnsubscribeOptionNullInterfaceForPassiveMode001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchUnsubscribeOptionNullInterfaceForPassiveMode001");
    DiscoveryBleDispatcherInterface interfaceWithNullMedium = {
        .IsConcern = IsConcernA,
        .mediumInterface = nullptr,
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&interfaceWithNullMedium, &g_interfaceB);
    int32_t ret = interface->Unsubscribe(&g_sOption1);
    EXPECT_EQ(SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL, ret);
}

/*
 * @tc.name: BleDispatchStartAdvertiseNullInterface001
 * @tc.desc: test BleDispatchStartAdvertise with null interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchStartAdvertiseNullInterface001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchStartAdvertiseNullInterface001");
    DiscoveryBleDispatcherInterface interfaceWithNullMedium = {
        .IsConcern = IsConcernA,
        .mediumInterface = nullptr,
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&interfaceWithNullMedium, &g_interfaceB);
    int32_t ret = interface->StartAdvertise(&g_sOption1);
    EXPECT_EQ(SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL, ret);
}

/*
 * @tc.name: BleDispatchStopAdvertiseNullInterface001
 * @tc.desc: test BleDispatchStopAdvertise with null interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleDispatcherTest, BleDispatchStopAdvertiseNullInterface001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BleDispatchStopAdvertiseNullInterface001");
    DiscoveryBleDispatcherInterface interfaceWithNullMedium = {
        .IsConcern = IsConcernA,
        .mediumInterface = nullptr,
    };
    DiscoveryFuncInterface *interface = DiscBleInitForTest(&interfaceWithNullMedium, &g_interfaceB);
    int32_t ret = interface->StopAdvertise(&g_sOption1);
    EXPECT_EQ(SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL, ret);
}
} // namespace OHOS
