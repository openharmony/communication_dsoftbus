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
 
#include <securec.h>

#include <gtest/gtest.h>
#include <unistd.h>
#include "disc_coap.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "disc_manager.h"

using namespace testing::ext;
namespace OHOS {

static DiscoveryFuncInterface *g_discCoapFuncInterface = NULL;

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

/*
* @tc.name: testCoapPublish
* @tc.desc: test CoapPublish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscCoapTest, testCoapPublish001, TestSize.Level1)
{
    int32_t ret;
    bool ranging = true;
    
    PublishOption *option = (PublishOption*)SoftBusMalloc(sizeof(PublishOption));
    ASSERT_TRUE(option != nullptr);
    memset_s(option, sizeof(PublishOption), 0, sizeof(PublishOption));

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ret = g_discCoapFuncInterface->Publish(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    
    ranging = false;
    ret = g_discCoapFuncInterface->Publish(option);
    EXPECT_EQ(ret, SOFTBUS_OK);
    
    SoftBusFree(option);
}

/*
* @tc.name: testCoapUnPublish
* @tc.desc: test CoapUnPublish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscCoapTest, testCoapUnPublish001, TestSize.Level1)
{
    int32_t ret;
    
    PublishOption *option = (PublishOption*)SoftBusMalloc(sizeof(PublishOption));
    ASSERT_TRUE(option != nullptr);
    memset_s(option, sizeof(PublishOption), 0, sizeof(PublishOption));

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ret = g_discCoapFuncInterface->Unpublish(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_discCoapFuncInterface->Unpublish(option);
    EXPECT_EQ(ret, SOFTBUS_OK);
    
    SoftBusFree(option);
}

/*
* @tc.name: testCoapStartScan
* @tc.desc: test CoapStartScan
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscCoapTest, testCoapStartScan001, TestSize.Level1)
{
    int32_t ret;
    
    PublishOption *option = (PublishOption*)SoftBusMalloc(sizeof(PublishOption));
    ASSERT_TRUE(option != nullptr);
    memset_s(option, sizeof(PublishOption), 0, sizeof(PublishOption));

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ret = g_discCoapFuncInterface->StartScan(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    
    ret = g_discCoapFuncInterface->StartScan(option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(option);
}

/*
* @tc.name: testCoapStopScan
* @tc.desc: test CoapStopScan
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscCoapTest, testCoapStopScan001, TestSize.Level1)
{
    int32_t ret;
    bool ranging = true;
    
    PublishOption *option = (PublishOption*)SoftBusMalloc(sizeof(PublishOption));
    ASSERT_TRUE(option != nullptr);
    memset_s(option, sizeof(PublishOption), 0, sizeof(PublishOption));

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ret = g_discCoapFuncInterface->StopScan(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    
    ret = g_discCoapFuncInterface->StopScan(option);
    
    ranging = false;
    ret = g_discCoapFuncInterface->StopScan(option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(option);
}

/*
* @tc.name: testCoapStartAdvertise
* @tc.desc: test CoapStartAdvertise
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscCoapTest, testCoapStartAdvertise001, TestSize.Level1)
{
    int32_t ret;

    SubscribeOption *option = (SubscribeOption*)SoftBusMalloc(sizeof(SubscribeOption));
    ASSERT_TRUE(option != nullptr);
    memset_s(option, sizeof(SubscribeOption), 0, sizeof(SubscribeOption));

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ret = g_discCoapFuncInterface->StartAdvertise(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_discCoapFuncInterface->StartAdvertise(option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(option);
}

/*
* @tc.name: testCoapStopAdvertise
* @tc.desc: test CoapStopAdvertise
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscCoapTest, testCoapStopAdvertise001, TestSize.Level1)
{
    int32_t ret;

    SubscribeOption *option = (SubscribeOption*)SoftBusMalloc(sizeof(SubscribeOption));
    ASSERT_TRUE(option != nullptr);
    memset_s(option, sizeof(SubscribeOption), 0, sizeof(SubscribeOption));

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ret = g_discCoapFuncInterface->StopAdvertise(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_discCoapFuncInterface->StopAdvertise(option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(option);
}

/*
* @tc.name: testCoapSubscribe
* @tc.desc: test CoapSubscribe
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscCoapTest, testCoapSubscribe001, TestSize.Level1)
{
    int32_t ret;

    SubscribeOption *option = (SubscribeOption*)SoftBusMalloc(sizeof(SubscribeOption));
    ASSERT_TRUE(option != nullptr);
    memset_s(option, sizeof(SubscribeOption), 0, sizeof(SubscribeOption));

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ret = g_discCoapFuncInterface->Subscribe(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_discCoapFuncInterface->Subscribe(option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(option);
}

/*
* @tc.name: testCoapUnsubscribe
* @tc.desc: test CoapUnsubscribe
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscCoapTest, testCoapUnsubscribe001, TestSize.Level1)
{
    int32_t ret;

    SubscribeOption *option = (SubscribeOption*)SoftBusMalloc(sizeof(SubscribeOption));
    ASSERT_TRUE(option != nullptr);
    memset_s(option, sizeof(SubscribeOption), 0, sizeof(SubscribeOption));

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ret = g_discCoapFuncInterface->Unsubscribe(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_discCoapFuncInterface->Unsubscribe(option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(option);
}
}