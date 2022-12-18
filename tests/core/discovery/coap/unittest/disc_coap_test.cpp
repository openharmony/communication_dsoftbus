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
#include <securec.h>
#include <unistd.h>

#include "disc_coap.h"
#include "disc_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"


using namespace testing::ext;
namespace OHOS {

static DiscoveryFuncInterface *g_discCoapFuncInterface = nullptr;

class DiscCoapTest : public testing::Test {
public:
    DiscCoapTest()
    {}
    ~DiscCoapTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void DiscCoapTest::SetUpTestCase(void)
{}

void DiscCoapTest::TearDownTestCase(void)
{}

static DiscInnerCallback g_discInnerCb = {
    .OnDeviceFound = NULL
};

static PublishOption testPubOption = {
    .freq = LOW,
    .capabilityBitmap = {64},
    .capabilityData = nullptr,
    .dataLen = 0,
    .ranging = false
};

static SubscribeOption testSubOption = {
    .freq = LOW,
    .isSameAccount = false,
    .isWakeRemote = false,
    .capabilityBitmap = {128},
    .capabilityData = nullptr,
    .dataLen = 0
};

/*
 * @tc.name: testCoapPublish001
 * @tc.desc: test CoapPublish
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, testCoapPublish001, TestSize.Level1)
{
    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    int32_t ret = g_discCoapFuncInterface->Publish(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = g_discCoapFuncInterface->Unpublish(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_discCoapFuncInterface->Publish(&testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->Unpublish(&testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testPubOption.ranging = true;
    ret = g_discCoapFuncInterface->Publish(&testPubOption);
    testPubOption.ranging = false;
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->Unpublish(&testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: testCoapStartScan001
 * @tc.desc: test CoapStartScan
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, testCoapStartScan001, TestSize.Level1)
{
    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    int32_t ret = g_discCoapFuncInterface->StartScan(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = g_discCoapFuncInterface->StopScan(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_discCoapFuncInterface->StartScan(&testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopScan(&testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testPubOption.ranging = true;
    ret = g_discCoapFuncInterface->StartScan(&testPubOption);
    testPubOption.ranging = false;
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopScan(&testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: testCoapStartAdvertise001
 * @tc.desc: test CoapStartAdvertise
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, testCoapStartAdvertise001, TestSize.Level1)
{
    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    int32_t ret = g_discCoapFuncInterface->StartAdvertise(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = g_discCoapFuncInterface->StopAdvertise(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_discCoapFuncInterface->StartAdvertise(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: testCoapSubscribe001
 * @tc.desc: test CoapSubscribe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, testCoapSubscribe001, TestSize.Level1)
{
    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    int32_t ret = g_discCoapFuncInterface->Subscribe(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = g_discCoapFuncInterface->Unsubscribe(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_discCoapFuncInterface->Subscribe(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->Unsubscribe(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: testCoapLinkStatusChanged001
 * @tc.desc: test CoapLinkStatusChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, testCoapLinkStatusChanged001, TestSize.Level1)
{
    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    int32_t ret = g_discCoapFuncInterface->StartAdvertise(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP);
    ret = g_discCoapFuncInterface->StartAdvertise(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: testCoapUpdateLocalDevInfo001
 * @tc.desc: test CoapUpdateLocalDevInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, testCoapUpdateLocalDevInfo001, TestSize.Level1)
{
    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    int32_t ret = g_discCoapFuncInterface->StartAdvertise(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_discCoapFuncInterface->UpdateLocalDeviceInfo(TYPE_LOCAL_DEVICE_NAME);
    ret = g_discCoapFuncInterface->StartAdvertise(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_discCoapFuncInterface->UpdateLocalDeviceInfo(TYPE_ACCOUNT);
    ret = g_discCoapFuncInterface->StartAdvertise(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}
}