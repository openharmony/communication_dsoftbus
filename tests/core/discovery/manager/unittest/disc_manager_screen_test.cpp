/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ble_mock.h"
#include "bus_center_client_proxy.h"
#include "coap_mock.h"
#include "constraint_mock.h"
#include "disc_interface.h"
#include "disc_log.h"
#include "disc_manager.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "usb_mock.h"
#include "nfc_mock.h"

using namespace testing::ext;
using testing::Return;

extern "C" {
int32_t ClientOnPublishLNNResult(const char *pkgName, int32_t pid, int32_t publishId, int32_t reason)
{
    (void)pkgName;
    (void)pid;
    (void)publishId;
    (void)reason;
    return SOFTBUS_OK;
}

int32_t ClientOnRefreshLNNResult(const char *pkgName, int32_t pid, int32_t refreshId, int32_t reason)
{
    (void)pkgName;
    (void)pid;
    (void)refreshId;
    (void)reason;
    return SOFTBUS_OK;
}
}

namespace OHOS {

class DiscManagerScreenTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        globalConstraintMock_ = new ConstraintMock();
        globalConstraintMock_->SetupStub();
    }

    static void TearDownTestCase()
    {
        delete globalConstraintMock_;
        globalConstraintMock_ = nullptr;
    }

    void SetUp() override
    {
        bleMock_.SetupStub();
        coapMock_.SetupStub();
        usbMock_.SetupStub();
        nfcMock_.SetupStub();
        EXPECT_EQ(DiscMgrInit(), SOFTBUS_OK);
    }

    void TearDown() override
    {
        DiscMgrDeinit();
    }

    static inline ConstraintMock *globalConstraintMock_ = nullptr;
    BleMock bleMock_;
    CoapMock coapMock_;
    UsbMock usbMock_;
    NfcMock nfcMock_;
};

/*
 * @tc.name: DiscOnScreenStatusChanged001
 * @tc.desc: test DiscOnScreenStatusChanged with invalid screenType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerScreenTest, DiscOnScreenStatusChanged001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscOnScreenStatusChanged001 begin ----");
    EXPECT_NO_FATAL_FAILURE(DiscOnScreenStatusChanged(static_cast<DiscScreenType>(-1), true));
    EXPECT_NO_FATAL_FAILURE(DiscOnScreenStatusChanged(DISC_SCREEN_TYPE_BUTT, true));
    DISC_LOGI(DISC_TEST, "DiscOnScreenStatusChanged001 end ----");
}

/*
 * @tc.name: DiscOnScreenStatusChanged002
 * @tc.desc: test DiscOnScreenStatusChanged screen on for DISC_SCREEN_CENTER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerScreenTest, DiscOnScreenStatusChanged002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscOnScreenStatusChanged002 begin ----");
    EXPECT_NO_FATAL_FAILURE(DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, true));
    DISC_LOGI(DISC_TEST, "DiscOnScreenStatusChanged002 end ----");
}

/*
 * @tc.name: DiscOnScreenStatusChanged003
 * @tc.desc: test DiscOnScreenStatusChanged screen off for DISC_SCREEN_CENTER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerScreenTest, DiscOnScreenStatusChanged003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscOnScreenStatusChanged003 begin ----");
    EXPECT_NO_FATAL_FAILURE(DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, false));
    DISC_LOGI(DISC_TEST, "DiscOnScreenStatusChanged003 end ----");
}

/*
 * @tc.name: DiscOnScreenStatusChanged004
 * @tc.desc: test DiscOnScreenStatusChanged screen on for DISC_SCREEN_PASSENGER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerScreenTest, DiscOnScreenStatusChanged004, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscOnScreenStatusChanged004 begin ----");
    EXPECT_NO_FATAL_FAILURE(DiscOnScreenStatusChanged(DISC_SCREEN_PASSENGER, true));
    DISC_LOGI(DISC_TEST, "DiscOnScreenStatusChanged004 end ----");
}

/*
 * @tc.name: DiscOnScreenStatusChanged005
 * @tc.desc: test DiscOnScreenStatusChanged screen off for DISC_SCREEN_PASSENGER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerScreenTest, DiscOnScreenStatusChanged005, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscOnScreenStatusChanged005 begin ----");
    EXPECT_NO_FATAL_FAILURE(DiscOnScreenStatusChanged(DISC_SCREEN_PASSENGER, false));
    DISC_LOGI(DISC_TEST, "DiscOnScreenStatusChanged005 end ----");
}

/*
 * @tc.name: DiscOnScreenStatusChanged006
 * @tc.desc: test DiscOnScreenStatusChanged screen on then off sequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerScreenTest, DiscOnScreenStatusChanged006, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscOnScreenStatusChanged006 begin ----");
    EXPECT_NO_FATAL_FAILURE(DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, true));
    EXPECT_NO_FATAL_FAILURE(DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, false));
    DISC_LOGI(DISC_TEST, "DiscOnScreenStatusChanged006 end ----");
}

/*
 * @tc.name: DiscPublishScreenOff001
 * @tc.desc: test PublishService rejected when screen off for active mode with BIZ_A capability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerScreenTest, DiscPublishScreenOff001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscPublishScreenOff001 begin ----");

    DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, false);

    PublishInfo info;
    info.publishId = 1;
    info.mode = DISCOVER_MODE_ACTIVE;
    info.medium = BLE;
    info.freq = LOW;
    info.capability = "osdCapability";
    info.capabilityData = nullptr;
    info.dataLen = 0;

    int32_t ret = DiscPublishService("TestPackage", &info, getpid());
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_MANAGER_SCREEN_OFF_REJECTED);

    DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, true);
    DISC_LOGI(DISC_TEST, "DiscPublishScreenOff001 end ----");
}

/*
 * @tc.name: DiscPublishScreenOff002
 * @tc.desc: test PublishService allowed with passive mode when screen off for BIZ_A capability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerScreenTest, DiscPublishScreenOff002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscPublishScreenOff002 begin ----");

    DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, false);

    PublishInfo info;
    info.publishId = 2;
    info.mode = DISCOVER_MODE_PASSIVE;
    info.medium = BLE;
    info.freq = LOW;
    info.capability = "osdCapability";
    info.capabilityData = nullptr;
    info.dataLen = 0;

    int32_t ret = DiscPublishService("TestPackage", &info, getpid());
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, true);
    DISC_LOGI(DISC_TEST, "DiscPublishScreenOff002 end ----");
}

/*
 * @tc.name: DiscSubscribeScreenOff001
 * @tc.desc: test StartDiscovery rejected when screen off for active mode with BIZ_A capability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerScreenTest, DiscSubscribeScreenOff001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSubscribeScreenOff001 begin ----");

    DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, false);

    SubscribeInfo info;
    info.subscribeId = 1;
    info.mode = DISCOVER_MODE_ACTIVE;
    info.medium = BLE;
    info.freq = LOW;
    info.capability = "osdCapability";
    info.capabilityData = nullptr;
    info.dataLen = 0;

    int32_t ret = DiscStartDiscovery("TestPackage", &info, nullptr, getpid());
    EXPECT_NE(ret, SOFTBUS_OK);

    DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, true);
    DISC_LOGI(DISC_TEST, "DiscSubscribeScreenOff001 end ----");
}

/*
 * @tc.name: DiscSubscribeScreenOff002
 * @tc.desc: test Subscribe allowed with passive mode when screen off for BIZ_A capability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerScreenTest, DiscSubscribeScreenOff002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSubscribeScreenOff002 begin ----");

    DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, false);

    SubscribeInfo info;
    info.subscribeId = 2;
    info.mode = DISCOVER_MODE_PASSIVE;
    info.medium = BLE;
    info.freq = LOW;
    info.capability = "osdCapability";
    info.capabilityData = nullptr;
    info.dataLen = 0;

    int32_t ret = DiscSubscribe(MODULE_LNN, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, true);
    DISC_LOGI(DISC_TEST, "DiscSubscribeScreenOff002 end ----");
}

/*
 * @tc.name: DiscScreenRecover001
 * @tc.desc: test screen on recovers passive discovery after screen off
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerScreenTest, DiscScreenRecover001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscScreenRecover001 begin ----");

    PublishInfo info;
    info.publishId = 3;
    info.mode = DISCOVER_MODE_PASSIVE;
    info.medium = BLE;
    info.freq = LOW;
    info.capability = "osdCapability";
    info.capabilityData = nullptr;
    info.dataLen = 0;

    EXPECT_EQ(DiscPublishService("TestPackage", &info, getpid()), SOFTBUS_OK);

    DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, false);
    DiscOnScreenStatusChanged(DISC_SCREEN_CENTER, true);

    DISC_LOGI(DISC_TEST, "DiscScreenRecover001 end ----");
}
} // namespace OHOS
