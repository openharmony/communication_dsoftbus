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

#include <gtest/gtest.h>
#include <securec.h>
#include <unistd.h>

#include "disc_coap.h"
#include "disc_manager.h"
#include "disc_nstackx_adapter.h"
#include "disc_coap_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using testing::Return;
namespace OHOS {

static constexpr uint32_t DDMP_CAPABILITY = 64;
static constexpr uint32_t OSD_CAPABILITY = 128;

static DiscoveryFuncInterface *g_discCoapFuncInterface = nullptr;

class DiscCoapTest : public testing::Test {
public:
    DiscCoapTest() { }
    ~DiscCoapTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void DiscCoapTest::SetUpTestCase(void) { }

void DiscCoapTest::TearDownTestCase(void) { }

static DiscInnerCallback g_discInnerCb = { .OnDeviceFound = nullptr };

static PublishOption g_testPubOption = {
    .freq = LOW,
    .capabilityBitmap = { DDMP_CAPABILITY },
    .capabilityData = nullptr,
    .dataLen = 0,
    .ranging = false
};

static SubscribeOption g_testSubOption = { .freq = LOW,
    .isSameAccount = false,
    .isWakeRemote = false,
    .capabilityBitmap = { OSD_CAPABILITY },
    .capabilityData = nullptr,
    .dataLen = 0 };

/*
 * @tc.name: CoapPublish001
 * @tc.desc: Test DiscCoapPublish and DiscCoapUnpublish should return SOFTBUS_INVALID_PARAM when given nullptr,
 *           should return SOFTBUS_OK when given valid PublishOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapPublish001, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    EXPECT_CALL(discCoapMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discCoapMock, LnnGetLocalStrInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);

    g_discCoapFuncInterface->LinkStatusChanged((LinkStatus)(-1), WLAN_IF);
    int32_t ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_PUBLISH_FAIL);

    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP, USB_IF + 1);
    ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_PUBLISH_FAIL);

    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP, WLAN_IF);
    ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL);

    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_DOWN, WLAN_IF);
    ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_PUBLISH_FAIL);

    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: CoapPublish002
 * @tc.desc: Test DiscCoapPublish and DiscCoapUnpublish should return SOFTBUS_INVALID_PARAM when given nullptr,
 *           should return SOFTBUS_OK when given valid PublishOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapPublish002, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP, 0);
    int32_t ret = g_discCoapFuncInterface->Publish(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = g_discCoapFuncInterface->Unpublish(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    g_testPubOption.capabilityBitmap[0] = (1 << APPROACH_CAPABILITY_BITMAP);
    ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL);

    g_testPubOption.capabilityBitmap[0] = DDMP_CAPABILITY;
    g_testPubOption.ranging = true;
    ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    g_testPubOption.ranging = false;
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: CoapPublish003
 * @tc.desc: Test DiscCoapPublish and DiscCoapUnpublish should return
 *           SOFTBUS_INVALID_PARAM when given nullptr g_publishMgr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapPublish003, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    DiscoveryFuncInterface *tmp = DiscCoapInit(nullptr);
    EXPECT_EQ(tmp, nullptr);
    int32_t ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: CoapPublish004
 * @tc.desc: Test DiscCoapPublish and DiscCoapUnpublish should return
 *           not SOFTBUS_OK when given invalid PublishOption.freq
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapPublish004, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP, 0);

    g_testPubOption.freq = LOW - 1;
    int32_t ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    g_testPubOption.freq = FREQ_BUTT + 1;
    ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_NE(ret, SOFTBUS_OK);

    g_testPubOption.freq = LOW;
    ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: CoapPublish005
 * @tc.desc: Test DiscCoapPublish and DiscCoapUnpublish should return
 *           SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL when given NSTACKX_INIT_STATE_START g_nstackInitState,
 *           should not return SOFTBUS_OK when given capabilityBitmap {0} and NSTACKX_INIT_STATE_START g_nstackInitState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapPublish005, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    int32_t ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP, 0);

    ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
    ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL);

    g_testPubOption.capabilityBitmap[0] = 0;
    ret = g_discCoapFuncInterface->Publish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL);
    ret = g_discCoapFuncInterface->Unpublish(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
    g_testPubOption.capabilityBitmap[0] = DDMP_CAPABILITY;
}

/*
 * @tc.name: CoapStartScan001
 * @tc.desc: test DiscCoapStartScan and DiscCoapStopScan should return SOFTBUS_INVALID_PARAM when given nullptr,
 *           should return SOFTBUS_OK when given valid PublishOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapStartScan001, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    int32_t ret = g_discCoapFuncInterface->StartScan(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = g_discCoapFuncInterface->StopScan(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_discCoapFuncInterface->StartScan(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopScan(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_testPubOption.ranging = true;
    ret = g_discCoapFuncInterface->StartScan(&g_testPubOption);
    g_testPubOption.ranging = false;
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopScan(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: CoapStartScan002
 * @tc.desc: Test DiscCoapStartScan and DiscCoapStopScan should return
 *           SOFTBUS_INVALID_PARAM when given nullptr g_publishMgr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapStartScan002, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    DiscoveryFuncInterface *tmp = DiscCoapInit(nullptr);
    EXPECT_EQ(tmp, nullptr);
    int32_t ret = g_discCoapFuncInterface->StartScan(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = g_discCoapFuncInterface->StopScan(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: CoapStartScan003
 * @tc.desc: Test DiscCoapStartScan and DiscCoapStopScan when should return
 *           SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL when given NSTACKX_INIT_STATE_START g_nstackInitState,
 *           should not return SOFTBUS_OK when given capabilityBitmap {0} and NSTACKX_INIT_STATE_START g_nstackInitState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapStartScan003, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    int32_t ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = g_discCoapFuncInterface->StartScan(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopScan(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
    ret = g_discCoapFuncInterface->StartScan(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL);
    ret = g_discCoapFuncInterface->StopScan(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL);

    g_testPubOption.capabilityBitmap[0] = 0;
    ret = g_discCoapFuncInterface->StartScan(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL);
    ret = g_discCoapFuncInterface->StopScan(&g_testPubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
    g_testPubOption.capabilityBitmap[0] = DDMP_CAPABILITY;
}

/*
 * @tc.name: CoapStartAdvertise001
 * @tc.desc: Test DiscCoapStartAdvertise and DiscCoapStopAdvertise
 *           should return SOFTBUS_INVALID_PARAM when given nullptr,
 *           should return SOFTBUS_OK when given valid SubscribeOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapStartAdvertise001, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP, 0);
    int32_t ret = g_discCoapFuncInterface->StartAdvertise(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = g_discCoapFuncInterface->StopAdvertise(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_DOWN, 0);
    ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: CoapStartAdvertise002
 * @tc.desc: Test DiscCoapStartAdvertise and DiscCoapStopAdvertise should return
 *           SOFTBUS_INVALID_PARAM when given nullptr g_publishMgr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapStartAdvertise002, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP, 0);
    DiscoveryFuncInterface *tmp = DiscCoapInit(nullptr);
    EXPECT_EQ(tmp, nullptr);
    int32_t ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: CoapStartAdvertise003
 * @tc.desc: Test DiscCoapStartAdvertise and DiscCoapStopAdvertise should return
 *           not SOFTBUS_OK when given invalid SubscribeOption.freq,
 *           should return not SOFTBUS_OK when given invalid SubscribeOption.freq
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapStartAdvertise003, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP, 0);

    g_testSubOption.freq = LOW - 1;
    int32_t ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    g_testSubOption.freq = FREQ_BUTT + 1;
    ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_NE(ret, SOFTBUS_OK);

    g_testSubOption.freq = LOW;
    ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: CoapStartAdvertise004
 * @tc.desc: Test DiscCoapStartAdvertise and DiscCoapStopAdvertise should return
 *           SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL when given NSTACKX_INIT_STATE_START g_nstackInitState,
 *           should return SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL when given capabilityBitmap {0} and
 *           NSTACKX_INIT_STATE_START g_nstackInitState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapStartAdvertise004, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    int32_t ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP, 0);

    ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
    ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL);

    g_testSubOption.capabilityBitmap[0] = 0;
    ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
    g_testSubOption.capabilityBitmap[0] = OSD_CAPABILITY;
}

/*
 * @tc.name: CoapSubscribe001
 * @tc.desc: test DiscCoapSubscribe and DiscCoapUnsubscribe should return SOFTBUS_INVALID_PARAM when given nullptr,
 *           should return SOFTBUS_OK when given valid SubscribeOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapSubscribe001, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    int32_t ret = g_discCoapFuncInterface->Subscribe(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = g_discCoapFuncInterface->Unsubscribe(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_discCoapFuncInterface->Subscribe(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->Unsubscribe(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: CoapSubscribe002
 * @tc.desc: Test DiscCoapSubscribe and DiscCoapUnsubscribe should return
 *           SOFTBUS_INVALID_PARAM when given nullptr g_publishMgr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapSubscribe002, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    DiscoveryFuncInterface *tmp = DiscCoapInit(nullptr);
    EXPECT_EQ(tmp, nullptr);
    int32_t ret = g_discCoapFuncInterface->Subscribe(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = g_discCoapFuncInterface->Unsubscribe(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: CoapSubscribe003
 * @tc.desc: Test DiscCoapSubscribe and DiscCoapUnsubscribe should return
 *           SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL when given NSTACKX_INIT_STATE_START g_nstackInitState,
 *           should return SOFTBUS_OK when given capabilityBitmap {0} and NSTACKX_INIT_STATE_START g_nstackInitState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, CoapSubscribe003, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    int32_t ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = g_discCoapFuncInterface->Subscribe(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->Unsubscribe(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
    ret = g_discCoapFuncInterface->Subscribe(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL);
    ret = g_discCoapFuncInterface->Unsubscribe(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL);

    g_testSubOption.capabilityBitmap[0] = 0;
    ret = g_discCoapFuncInterface->Subscribe(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->Unsubscribe(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
    g_testSubOption.capabilityBitmap[0] = OSD_CAPABILITY;
}

/*
 * @tc.name: CoapLinkStatusChanged001
 * @tc.desc: Test DiscCoapLinkStatusChanged should return SOFTBUS_OK when given LINK_STATUS_UP,
 *           should return SOFTBUS_OK when given LINK_STATUS_DOWN LinkStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, testCoapLinkStatusChanged001, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP, 0);
    int32_t ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP, 0);
    ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_DOWN, 0);
    ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}

/*
 * @tc.name: CoapUpdateLocalDevInfo001
 * @tc.desc: Test DiscCoapUpdateLocalDevInfo should return SOFTBUS_OK when given TYPE_LOCAL_DEVICE_NAME,
 *           should return SOFTBUS_OK when given TYPE_ACCOUNT InfoTypeChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscCoapTest, testCoapUpdateLocalDevInfo001, TestSize.Level1)
{
    DiscCoapMock discCoapMock;
    discCoapMock.SetupSuccessStub();

    g_discCoapFuncInterface = DiscCoapInit(&g_discInnerCb);
    ASSERT_NE(g_discCoapFuncInterface, nullptr);
    g_discCoapFuncInterface->LinkStatusChanged(LINK_STATUS_UP, 0);
    int32_t ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_discCoapFuncInterface->UpdateLocalDeviceInfo(TYPE_LOCAL_DEVICE_NAME);
    ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_discCoapFuncInterface->UpdateLocalDeviceInfo(TYPE_ACCOUNT);
    ret = g_discCoapFuncInterface->StartAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_discCoapFuncInterface->StopAdvertise(&g_testSubOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapDeinit();
    g_discCoapFuncInterface = nullptr;
}
} // namespace OHOS