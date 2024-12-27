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

#include "bus_center_manager.h"
#include "bus_center_mock.h"
#include "disc_manager_mock.h"
#include "lnn_coap_discovery_impl.c"
#include "lnn_coap_discovery_impl.h"
#include "lnn_discovery_manager.c"
#include "lnn_discovery_manager.h"
#include "lnn_hichain_mock.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
const uint16_t TEST_PORT = 1234;

class LNNDiscoveryInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNDiscoveryInterfaceTest::SetUpTestCase() { }

void LNNDiscoveryInterfaceTest::TearDownTestCase() { }

void LNNDiscoveryInterfaceTest::SetUp() { }

void LNNDiscoveryInterfaceTest::TearDown() { }

static int32_t OnRefreshDeviceFoundTest(
    const char *pkgName, const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    return SOFTBUS_OK;
}

static IServerDiscInnerCallback g_discInnerCb = {
    .OnServerDeviceFound = OnRefreshDeviceFoundTest,
};

static int32_t LnnCoapTest(void)
{
    return SOFTBUS_INVALID_PARAM;
}

static int32_t LnnCoapFuncTest(void)
{
    return SOFTBUS_OK;
}

/*
 * @tc.name: LNN_PUBLISH_SERVICE_TEST_001
 * @tc.desc: device found test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_PUBLISH_SERVICE_TEST_001, TestSize.Level1)
{
    DeviceInfo device;
    InnerDeviceInfoAddtions additions;

    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&additions, sizeof(InnerDeviceInfoAddtions), 0, sizeof(InnerDeviceInfoAddtions));
    BusCenterMock busCenterMock;
    busCenterMock.SetupSuccessStub();
    DeviceFound(nullptr, &additions);
    DeviceFound(&device, &additions);
    device.addr[0].type = CONNECTION_ADDR_WLAN;
    DeviceFound(&device, &additions);
    device.addr[0].type = CONNECTION_ADDR_ETH;
    DeviceFound(&device, &additions);
    device.addr[0].type = CONNECTION_ADDR_BR;
    DeviceFound(&device, &additions);
    device.addr[0].info.ip.port = 22;
    DeviceFound(&device, &additions);

    const char *pkgName = "testpkgName";
    PublishInfo info;
    bool isInnerRequest = false;
    DiscManagerInterfaceMock discMock;
    (void)memset_s(&info, sizeof(PublishInfo), 0, sizeof(PublishInfo));
    EXPECT_CALL(discMock, DiscPublishService).WillRepeatedly(Return(SOFTBUS_DISCOVER_MANAGER_NOT_INIT));
    int32_t ret = LnnPublishService(pkgName, &info, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_MANAGER_NOT_INIT);
}

/*
 * @tc.name: LNN_PUBLISH_SERVICE_TEST_002
 * @tc.desc: lnn publish service test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_PUBLISH_SERVICE_TEST_002, TestSize.Level1)
{
    const char *pkgName = "testpkgName";
    PublishInfo info;
    bool isInnerRequest = false;
    DiscManagerInterfaceMock discMock;
    int32_t ret = 0;

    (void)memset_s(&info, sizeof(PublishInfo), 0, sizeof(PublishInfo));
    EXPECT_CALL(discMock, DiscPublishService).WillRepeatedly(Return(SOFTBUS_DISCOVER_MANAGER_NOT_INIT));
    ret = LnnPublishService(pkgName, &info, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_MANAGER_NOT_INIT);
    EXPECT_CALL(discMock, DiscPublishService).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnPublishService(pkgName, &info, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    isInnerRequest = true;
    EXPECT_CALL(discMock, DiscStartScan).WillRepeatedly(Return(SOFTBUS_DISCOVER_MANAGER_NOT_INIT));
    ret = LnnPublishService(pkgName, &info, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_MANAGER_NOT_INIT);
    EXPECT_CALL(discMock, DiscStartScan).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnPublishService(pkgName, &info, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_UNPUBLISH_SERVICE_TEST_001
 * @tc.desc: lnn unpublish service test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_UNPUBLISH_SERVICE_TEST_001, TestSize.Level1)
{
    const char *pkgName = "testpkgName";
    int32_t publishId = 0;
    bool isInnerRequest = false;
    DiscManagerInterfaceMock discMock;
    int32_t ret = 0;

    EXPECT_CALL(discMock, DiscUnPublishService).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnUnPublishService(pkgName, publishId, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_PUBLISH_FAIL);
    EXPECT_CALL(discMock, DiscUnPublishService).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnUnPublishService(pkgName, publishId, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    isInnerRequest = true;
    EXPECT_CALL(discMock, DiscUnpublish).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnUnPublishService(pkgName, publishId, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_PUBLISH_FAIL);
    EXPECT_CALL(discMock, DiscUnpublish).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnUnPublishService(pkgName, publishId, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_START_DISC_DEVICE_TEST_001
 * @tc.desc: lnn start disc device test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_START_DISC_DEVICE_TEST_001, TestSize.Level1)
{
    const char *pkgName = "testpkgName";
    SubscribeInfo info;
    bool isInnerRequest = false;
    DiscManagerInterfaceMock discMock;
    int32_t ret = 0;

    InnerCallback cb = {
        .serverCb = g_discInnerCb,
    };
    (void)memset_s(&info, sizeof(SubscribeInfo), 0, sizeof(SubscribeInfo));
    EXPECT_CALL(discMock, DiscStartDiscovery).WillRepeatedly(Return(SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL));
    ret = LnnStartDiscDevice(pkgName, &info, &cb, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL);
    EXPECT_CALL(discMock, DiscStartDiscovery).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnStartDiscDevice(pkgName, &info, &cb, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    isInnerRequest = true;
    EXPECT_CALL(discMock, DiscSetDiscoverCallback).WillRepeatedly(Return(SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE));
    ret = LnnStartDiscDevice(pkgName, &info, &cb, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE);
    EXPECT_CALL(discMock, DiscSetDiscoverCallback).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, DiscStartAdvertise).WillRepeatedly(Return(SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL));
    ret = LnnStartDiscDevice(pkgName, &info, &cb, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL);
    EXPECT_CALL(discMock, DiscSetDiscoverCallback).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, DiscStartAdvertise).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnStartDiscDevice(pkgName, &info, &cb, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_STOP_DISC_DEVICE_TEST_001
 * @tc.desc: lnn stop disc device test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_STOP_DISC_DEVICE_TEST_001, TestSize.Level1)
{
    const char *pkgName = "testpkgName";
    int32_t subscribeId = 0;
    bool isInnerRequest = false;
    DiscManagerInterfaceMock discMock;
    int32_t ret = 0;

    EXPECT_CALL(discMock, DiscStopDiscovery).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnStopDiscDevice(pkgName, subscribeId, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);
    EXPECT_CALL(discMock, DiscStopDiscovery).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnStopDiscDevice(pkgName, subscribeId, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    isInnerRequest = true;
    EXPECT_CALL(discMock, DiscStopAdvertise).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnStopDiscDevice(pkgName, subscribeId, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);
    EXPECT_CALL(discMock, DiscStopAdvertise).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnStopDiscDevice(pkgName, subscribeId, isInnerRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_START_PUBLISH_TEST_001
 * @tc.desc: lnn start publish test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_START_PUBLISH_TEST_001, TestSize.Level1)
{
    g_discoveryImpl[0].StopPublishImpl = nullptr;
    LnnStopPublish();
    g_discoveryImpl[0].StopPublishImpl = LnnCoapTest;
    LnnStopPublish();
    g_discoveryImpl[0].StopPublishImpl = LnnCoapFuncTest;
    LnnStopPublish();

    g_discoveryImpl[0].StartPublishImpl = nullptr;
    int32_t ret = LnnStartPublish();
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_discoveryImpl[0].StartPublishImpl = LnnCoapTest;
    ret = LnnStartPublish();
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL);
    g_discoveryImpl[0].StartPublishImpl = LnnCoapFuncTest;
    ret = LnnStartPublish();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_START_DISCOVERY_TEST_001
 * @tc.desc: lnn start discovery test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_START_DISCOVERY_TEST_001, TestSize.Level1)
{
    g_discoveryImpl[0].StopDiscoveryImpl = nullptr;
    LnnStopDiscovery();
    g_discoveryImpl[0].StopDiscoveryImpl = LnnCoapTest;
    LnnStopDiscovery();
    g_discoveryImpl[0].StopDiscoveryImpl = LnnCoapFuncTest;
    LnnStopDiscovery();

    g_discoveryImpl[0].StartDiscoveryImpl = nullptr;
    int32_t ret = LnnStartDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_discoveryImpl[0].StartDiscoveryImpl = LnnCoapTest;
    ret = LnnStartDiscovery();
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL);
    g_discoveryImpl[0].StartDiscoveryImpl = LnnCoapFuncTest;
    ret = LnnStartDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INIT_COAP_DISCOVERY_TEST_001
 * @tc.desc: lnn init coap discovery test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_INIT_COAP_DISCOVERY_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnInitCoapDiscovery(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_INIT_COAP_DISCOVERY_TEST_002
 * @tc.desc: lnn init coap discovery test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_INIT_COAP_DISCOVERY_TEST_002, TestSize.Level1)
{
    LnnDiscoveryImplCallback callback;
    int32_t ret = LnnInitCoapDiscovery(&callback);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_START_COAP_DISCOVERY_TEST_001
 * @tc.desc: lnn start coap discovery test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_START_COAP_DISCOVERY_TEST_001, TestSize.Level1)
{
    DiscManagerInterfaceMock discMock;
    int32_t ret;
    EXPECT_CALL(discMock, DiscSetDiscoverCallback).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnStartCoapDiscovery();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(discMock, DiscSetDiscoverCallback).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, DiscStartAdvertise).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnStartCoapDiscovery();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(discMock, DiscSetDiscoverCallback).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, DiscStartAdvertise).WillOnce(Return(SOFTBUS_OK));
    ret = LnnStartCoapDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(discMock, DiscStopAdvertise).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnStopCoapDiscovery();
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);
    EXPECT_CALL(discMock, DiscStopAdvertise).WillOnce(Return(SOFTBUS_OK));
    ret = LnnStopCoapDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_START_COAP_PUBLISH_TEST_001
 * @tc.desc: lnn start coap publish test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_START_COAP_PUBLISH_TEST_001, TestSize.Level1)
{
    DiscManagerInterfaceMock discMock;
    int32_t ret;
    EXPECT_CALL(discMock, DiscStartScan).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnStartCoapPublish();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(discMock, DiscStartScan).WillOnce(Return(SOFTBUS_OK));
    ret = LnnStartCoapPublish();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(discMock, DiscUnpublish).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnStopCoapPublish();
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_PUBLISH_FAIL);
    EXPECT_CALL(discMock, DiscUnpublish).WillOnce(Return(SOFTBUS_OK));
    ret = LnnStopCoapPublish();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GET_CONNECT_DEVICE_INFO_TEST_001
 * @tc.desc: get connect device info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, GET_CONNECT_DEVICE_INFO_TEST_001, TestSize.Level1)
{
    DeviceInfo devInfo;
    ConnectionAddr addr;
    int32_t ret = GetConnectDeviceInfo(&devInfo, &addr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_CHECK_DISCOVERY_DEVICE_TEST_001
 * @tc.desc: lnn check discovery device test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_CHECK_DISCOVERY_DEVICE_TEST_001, TestSize.Level1)
{
    DeviceInfo devInfo;
    devInfo.addr[0].type = CONNECTION_ADDR_BR;
    int32_t ret = LnnCheckDiscoveryDeviceInfo(&devInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    devInfo.addr[0].type = CONNECTION_ADDR_BLE;
    ret = LnnCheckDiscoveryDeviceInfo(&devInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    devInfo.addr[0].type = CONNECTION_ADDR_SESSION;
    ret = LnnCheckDiscoveryDeviceInfo(&devInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    devInfo.addr[0].type = CONNECTION_ADDR_MAX;
    ret = LnnCheckDiscoveryDeviceInfo(&devInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    devInfo.addr[0].type = CONNECTION_ADDR_WLAN;
    devInfo.addr[0].info.ip.port = 0;
    ret = LnnCheckDiscoveryDeviceInfo(&devInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    devInfo.addr[0].type = CONNECTION_ADDR_ETH;
    devInfo.addr[0].info.ip.port = 0;
    ret = LnnCheckDiscoveryDeviceInfo(&devInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_CHECK_DISCOVERY_DEVICE_TEST_002
 * @tc.desc: lnn check discovery device test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDiscoveryInterfaceTest, LNN_CHECK_DISCOVERY_DEVICE_TEST_002, TestSize.Level1)
{
    DeviceInfo devInfo;
    devInfo.addr[0].type = CONNECTION_ADDR_WLAN;
    devInfo.addr[0].info.ip.port = TEST_PORT;
    int32_t ret = LnnCheckDiscoveryDeviceInfo(&devInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
