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

#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

#include "ble_mock.h"
#include "bus_center_mock.h"
#include "disc_ble.h"
#include "disc_ble_utils.h"
#include "disc_log.h"
#include "message_handler.h"
#include "securec.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using testing::_;
using testing::NiceMock;
using testing::NotNull;
using testing::Return;

namespace OHOS {
class DiscBleTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        LooperInit();
    }

    static void TearDownTestCase()
    {
        LooperDeinit();
    }

    void SetUp() override { }
    void TearDown() override { }

    static inline std::string g_customCapData = R"({"castPlus":"1122", "extCustData":"1122", "preLinkType":"HML"})";
    static inline DeviceInfo g_foundDeviceInfo;
    static constexpr char FOUND_DEVICE_ID[] = "e831f7630b7619ae";
    static inline std::string validRefreshData = R"({"discType":"handle"})";
    static inline std::string invalidRefreshData = R"({"discType":"unkonw"})";
};

static void OnDeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    DISC_LOGI(DISC_TEST, "OnDeviceFound, devId=%{public}s", device->devId);
    DiscBleTest::g_foundDeviceInfo = *device;
}

static DiscInnerCallback g_discInnerCallback = {
    .OnDeviceFound = OnDeviceFound,
};

static DiscoveryBleDispatcherInterface *g_interface;

static PublishOption GetPublishOptionForCastPlus()
{
    PublishOption option {};
    option.freq = LOW;
    option.capabilityData = reinterpret_cast<uint8_t *>(DiscBleTest::g_customCapData.data());
    option.dataLen = DiscBleTest::g_customCapData.length();

    SetCapBitMapPos(CAPABILITY_NUM, option.capabilityBitmap, CASTPLUS_CAPABILITY_BITMAP);
    return option;
}

static SubscribeOption GetSubscribeOptionForCastPlus()
{
    SubscribeOption option {};
    option.freq = LOW;
    option.isSameAccount = false;
    option.isWakeRemote = false;
    option.capabilityData = reinterpret_cast<uint8_t *>(DiscBleTest::g_customCapData.data());
    option.dataLen = DiscBleTest::g_customCapData.length();

    SetCapBitMapPos(CAPABILITY_NUM, option.capabilityBitmap, CASTPLUS_CAPABILITY_BITMAP);
    return option;
}

static SubscribeOption GetSubscribeOptionForCastPlusGetHandle(const std::string custData)
{
    SubscribeOption option {};
    option.freq = LOW;
    option.isSameAccount = false;
    option.isWakeRemote = false;
    option.capabilityData = reinterpret_cast<uint8_t *>(const_cast<char *>(custData.data()));
    option.dataLen = custData.length();

    SetCapBitMapPos(CAPABILITY_NUM, option.capabilityBitmap, CASTPLUS_CAPABILITY_BITMAP);
    return option;
}

static SubscribeOption GetSubscribeOptionForOsd()
{
    SubscribeOption option {};
    option.freq = LOW;
    option.isSameAccount = false;
    option.isWakeRemote = false;
    option.capabilityData = reinterpret_cast<uint8_t *>(DiscBleTest::g_customCapData.data());
    option.dataLen = DiscBleTest::g_customCapData.length();

    SetCapBitMapPos(CAPABILITY_NUM, option.capabilityBitmap, OSD_CAPABILITY_BITMAP);
    return option;
}

/*
 * @tc.name: DiscBleInit001
 * @tc.desc: invalid input parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleInit001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleInit001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    EXPECT_EQ(DiscSoftBusBleInit(nullptr), nullptr);

    DiscInnerCallback callback;
    callback.OnDeviceFound = nullptr;
    EXPECT_EQ(DiscSoftBusBleInit(&callback), nullptr);
    DISC_LOGI(DISC_TEST, "DiscBleInit001 end ----");
}

/*
 * @tc.name: DiscBleInit002
 * @tc.desc: scan listener init failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleInit002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleInit002 begin ----");
    {
        BleMock bleMock;
        bleMock.SetupSuccessStub();
        EXPECT_CALL(bleMock, InitBroadcastMgr).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscSoftBusBleInit(&g_discInnerCallback), nullptr);
    }
    {
        BleMock bleMock;
        bleMock.SetupSuccessStub();
        EXPECT_CALL(bleMock, InitBroadcastMgr).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(bleMock, RegisterScanListener).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscSoftBusBleInit(&g_discInnerCallback), nullptr);
    }
    {
        BleMock bleMock;
        bleMock.SetupSuccessStub();
        EXPECT_CALL(bleMock, InitBroadcastMgr).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(bleMock, RegisterScanListener).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(bleMock, SoftBusAddBtStateListener).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscSoftBusBleInit(&g_discInnerCallback), nullptr);
    }
    {
        BleMock bleMock;
        bleMock.SetupSuccessStub();
        EXPECT_CALL(bleMock, InitBroadcastMgr).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(bleMock, RegisterScanListener).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(bleMock, SoftBusAddBtStateListener).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(bleMock, SetScanFilter).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscSoftBusBleInit(&g_discInnerCallback), nullptr);
    }
    {
        BleMock bleMock;
        bleMock.SetupSuccessStub();
        EXPECT_CALL(bleMock, InitBroadcastMgr).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(bleMock, RegisterScanListener).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(bleMock, SoftBusAddBtStateListener).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(bleMock, SetScanFilter).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(bleMock, RegisterBroadcaster).WillRepeatedly(Return(SOFTBUS_DISCOVER_TEST_CASE_ERRCODE));
        EXPECT_EQ(DiscSoftBusBleInit(&g_discInnerCallback), nullptr);
    }
    DISC_LOGI(DISC_TEST, "DiscBleInit002 end ----");
}

/*
 * @tc.name: DiscBleInit003
 * @tc.desc: valid parameter, init successful
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleInit003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleInit003 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    g_interface = DiscSoftBusBleInit(&g_discInnerCallback);
    EXPECT_NE(g_interface, nullptr);
    DISC_LOGI(DISC_TEST, "DiscBleInit003 end ----");
}

/*
 * @tc.name: StartActiveDiscovery001
 * @tc.desc: start active discovery successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, StartActiveDiscovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "StartActiveDiscovery001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();
    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_OK);
    EXPECT_EQ(bleMock.GetAsyncAdvertiseResult(), true);

    BleMock::TurnOffBt();
    EXPECT_EQ(bleMock.IsScanning(), false);

    BleMock::TurnOnBt();
    EXPECT_EQ(bleMock.IsScanning(), true);

    // Re-setup BusCenterMock after BT toggle
    busMock.SetupSuccessStub();

    DISC_LOGI(DISC_TEST, "StartActiveDiscovery001 end ----");
}

/*
 * @tc.name: StartActiveDiscovery002
 * @tc.desc: start the second capability to update advertiser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, StartActiveDiscovery002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "StartActiveDiscovery002 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, UpdateBroadcasting(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForActiveDiscovery);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    SubscribeOption option = GetSubscribeOptionForOsd();
    const char *pkgName = "ohos.distributedhardware.devicemanager";
    const char *nameData = "{\"raw\": \"My Device\",\"name18\": \"Display Name 18\","
        "\"name21\": \"Display Name 21\",\"name24\": \"Display Name 24\"}";
    DiscSetDisplayName(pkgName, nameData, strlen(nameData));
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_OK);
    EXPECT_EQ(bleMock.GetAsyncAdvertiseResult(), true);

    DISC_LOGI(DISC_TEST, "StartActiveDiscovery002 end ----");
}

/*
 * @tc.name: StartActiveDiscovery003
 * @tc.desc: start the second capability to update advertiser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, StartActiveDiscovery003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "StartActiveDiscovery003 begin ----");

    SubscribeOption option = GetSubscribeOptionForCastPlusGetHandle(validRefreshData);

    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);

    option = GetSubscribeOptionForCastPlusGetHandle(invalidRefreshData);
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_INVALID_PARAM);
    DISC_LOGI(DISC_TEST, "StartActiveDiscovery003 end ----");
}

/*
 * @tc.name: UpdateLocalDeviceInfo001
 * @tc.desc: update local device info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, UpdateLocalDeviceInfo001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "UpdateLocalDeviceInfo001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, UpdateBroadcasting(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForActiveDiscovery);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    ASSERT_NE(g_interface->mediumInterface->UpdateLocalDeviceInfo, nullptr);
    g_interface->mediumInterface->UpdateLocalDeviceInfo(TYPE_LOCAL_DEVICE_NAME);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    DISC_LOGI(DISC_TEST, "UpdateLocalDeviceInfo001 end ----");
}

/*
 * @tc.name: ReceivePassivePublishPacket001
 * @tc.desc: receive passive publish packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, ReceivePassivePublishPacket001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ReceivePassivePublishPacket001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::InjectPassiveNonPacket();

    EXPECT_EQ(strcmp(g_foundDeviceInfo.devId, FOUND_DEVICE_ID), 0);
    EXPECT_EQ(g_foundDeviceInfo.capabilityBitmap[0], 1 << CASTPLUS_CAPABILITY_BITMAP);
    (void)memset_s(&g_foundDeviceInfo, sizeof(g_foundDeviceInfo), 0, sizeof(DeviceInfo));
    DISC_LOGI(DISC_TEST, "ReceivePassivePublishPacket001 end ----");
}

/*
 * @tc.name: ReceivePassivePublishPacketOfCust001
 * @tc.desc: receive passive publish packet for test parse cust data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, ReceivePassivePublishPacketOfCust001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ReceivePassivePublishPacketOfCust001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::InjectPassiveNonPacketOfCust();

    EXPECT_EQ(strcmp(g_foundDeviceInfo.devId, FOUND_DEVICE_ID), 0);
    EXPECT_EQ(g_foundDeviceInfo.capabilityBitmap[0], 1 << CASTPLUS_CAPABILITY_BITMAP);
    (void)memset_s(&g_foundDeviceInfo, sizeof(g_foundDeviceInfo), 0, sizeof(DeviceInfo));
    DISC_LOGI(DISC_TEST, "ReceivePassivePublishPacketOfCust001 end ----");
}

/*
 * @tc.name: StopActiveDiscovery001
 * @tc.desc: stop active discovery successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, StopActiveDiscovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "StopActiveDiscovery001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, UpdateBroadcasting(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForActiveDiscovery);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);
    option = GetSubscribeOptionForOsd();
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    DISC_LOGI(DISC_TEST, "StopActiveDiscovery001 end ----");
}

/*
 * @tc.name: StartActiveDiscovery001
 * @tc.desc: start active discovery successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, StartPassiveDiscovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "StartPassiveDiscovery001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    BleMock::InjectActiveNonPacket();

    EXPECT_EQ(strcmp(g_foundDeviceInfo.devId, FOUND_DEVICE_ID), 0);
    EXPECT_EQ(g_foundDeviceInfo.capabilityBitmap[0], 1 << CASTPLUS_CAPABILITY_BITMAP);
    (void)memset_s(&g_foundDeviceInfo, sizeof(g_foundDeviceInfo), 0, sizeof(DeviceInfo));
    DISC_LOGI(DISC_TEST, "StartPassiveDiscovery001 end ----");
}

/*
 * @tc.name: StopPassiveDiscovery001
 * @tc.desc: stop active discovery successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, StopPassiveDiscovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "StopPassiveDiscovery001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option), SOFTBUS_OK);

    option = GetSubscribeOptionForOsd();
    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    DISC_LOGI(DISC_TEST, "StopPassiveDiscovery001 end ----");
}

/*
 * @tc.name: StartActivePublish001
 * @tc.desc: start active publish successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, StartActivePublish001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "StartActivePublish001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    PublishOption option = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Publish(&option), SOFTBUS_OK);
    EXPECT_EQ(bleMock.GetAsyncAdvertiseResult(), true);

    DISC_LOGI(DISC_TEST, "StartActivePublish001 end ----");
}

/*
 * @tc.name: StopActivePublish001
 * @tc.desc: stop active publish successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, StopActivePublish001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "StopActivePublish001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    PublishOption option = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Unpublish(&option), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    DISC_LOGI(DISC_TEST, "StopActivePublish001 end ----");
}

/*
 * @tc.name: StartPassivePublish001
 * @tc.desc: start passive publish successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, StartPassivePublish001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "StartPassivePublish001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    PublishOption option = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartScan(&option), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    DISC_LOGI(DISC_TEST, "StartPassivePublish001 end ----");
}

/*
 * @tc.name: ReceiveActiveDiscoveryPacket001
 * @tc.desc: when receiving active discovery packet, handle it successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, ReceiveActiveDiscoveryPacket001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ReceiveActiveDiscoveryPacket001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, UpdateBroadcasting(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForPassivePublish);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::InjectActiveConPacket();

    EXPECT_EQ(bleMock.GetAsyncAdvertiseResult(), true);
    DISC_LOGI(DISC_TEST, "ReceiveActiveDiscoveryPacket001 end ----");
}

/*
 * @tc.name: StopPassivePublish001
 * @tc.desc: stop passive publish successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, StopPassivePublish001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "StopPassivePublish001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    PublishOption option = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StopScan(&option), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    DISC_LOGI(DISC_TEST, "StopPassivePublish001 end ----");
}

/*
 * @tc.name: IsConcernCapability001
 * @tc.desc: test ble discovery supported capability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, IsConcernCapability001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "IsConcernCapability001 begin ----");
    uint32_t capability = 0;
    SetCapBitMapPos(1, &capability, CASTPLUS_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->IsConcern(capability), true);
    capability = 0;
    SetCapBitMapPos(1, &capability, DVKIT_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->IsConcern(capability), true);
    capability = 0;
    SetCapBitMapPos(1, &capability, OSD_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->IsConcern(capability), true);
    capability = 0;
    SetCapBitMapPos(1, &capability, SHARE_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->IsConcern(capability), false);
    DISC_LOGI(DISC_TEST, "IsConcernCapability001 end ----");
}

/*
 * @tc.name: DiscBleFrequencyTest001
 * @tc.desc: test different frequency settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleFrequencyTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleFrequencyTest001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Test LOW frequency
    SubscribeOption optionLow = GetSubscribeOptionForCastPlus();
    optionLow.freq = LOW;
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&optionLow), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&optionLow), SOFTBUS_OK);

    // Test MID frequency
    SubscribeOption optionMid = GetSubscribeOptionForCastPlus();
    optionMid.freq = MID;
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&optionMid), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&optionMid), SOFTBUS_OK);

    // Test HIGH frequency
    SubscribeOption optionHigh = GetSubscribeOptionForCastPlus();
    optionHigh.freq = HIGH;
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&optionHigh), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&optionHigh), SOFTBUS_OK);

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleFrequencyTest001 end ----");
}

/*
 * @tc.name: DiscBleCapabilityCombination001
 * @tc.desc: test multiple capability combinations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleCapabilityCombination001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleCapabilityCombination001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Test CastPlus capability
    PublishOption option1 = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Publish(&option1), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_interface->mediumInterface->Unpublish(&option1), SOFTBUS_OK);

    // Test OSD capability
    PublishOption option2;
    option2.freq = LOW;
    option2.capabilityData = reinterpret_cast<uint8_t *>(g_customCapData.data());
    option2.dataLen = g_customCapData.length();
    SetCapBitMapPos(CAPABILITY_NUM, option2.capabilityBitmap, OSD_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->mediumInterface->Publish(&option2), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_interface->mediumInterface->Unpublish(&option2), SOFTBUS_OK);

    // Test DVKit capability
    PublishOption option3;
    option3.freq = LOW;
    option3.capabilityData = reinterpret_cast<uint8_t *>(g_customCapData.data());
    option3.dataLen = g_customCapData.length();
    SetCapBitMapPos(CAPABILITY_NUM, option3.capabilityBitmap, DVKIT_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->mediumInterface->Publish(&option3), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_interface->mediumInterface->Unpublish(&option3), SOFTBUS_OK);

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleCapabilityCombination001 end ----");
}

/*
 * @tc.name: DiscBleConcurrentPublish001
 * @tc.desc: test concurrent publish and subscribe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleConcurrentPublish001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleConcurrentPublish001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Start publish
    PublishOption pubOption = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Publish(&pubOption), SOFTBUS_OK);

    // Start subscribe
    SubscribeOption subOption = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&subOption), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Stop both
    EXPECT_EQ(g_interface->mediumInterface->Unpublish(&pubOption), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&subOption), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleConcurrentPublish001 end ----");
}

/*
 * @tc.name: DiscBleStopWithoutStart001
 * @tc.desc: test stop operations without start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleStopWithoutStart001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleStopWithoutStart001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Try to stop without starting - should handle gracefully
    PublishOption pubOption = GetPublishOptionForCastPlus();
    g_interface->mediumInterface->Unpublish(&pubOption);

    SubscribeOption subOption = GetSubscribeOptionForCastPlus();
    g_interface->mediumInterface->Unsubscribe(&subOption);
    g_interface->mediumInterface->StopAdvertise(&subOption);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleStopWithoutStart001 end ----");
}

/*
 * @tc.name: DiscBleRepeatedStartStop001
 * @tc.desc: test repeated start and stop operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleRepeatedStartStop001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleRepeatedStartStop001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    PublishOption option = GetPublishOptionForCastPlus();

    // Repeated start and stop
    for (int32_t i = 0; i < 3; i++) {
        EXPECT_EQ(g_interface->mediumInterface->Publish(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        EXPECT_EQ(g_interface->mediumInterface->Unpublish(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleRepeatedStartStop001 end ----");
}

/*
 * @tc.name: DiscBleBtStateChange001
 * @tc.desc: test Bluetooth state change during operation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleBtStateChange001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleBtStateChange001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_OK);

    // Re-setup BusCenterMock after BT toggle
    busMock.SetupSuccessStub();

    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    // Use longer wait time (2000ms) for BT state toggle test cases
    BleMock::WaitForBleMockSafeDestruction(2000);
    DISC_LOGI(DISC_TEST, "DiscBleBtStateChange001 end ----");
}

/*
 * @tc.name: DiscBleCapabilityDataTest001
 * @tc.desc: test various capability data formats
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleCapabilityDataTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleCapabilityDataTest001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Test with different capability data
    std::vector<std::string> testDataList = {
        R"({"test":"data"})",
        R"({"castPlus":"test","extCustData":"custom"})",
        R"({"key1":"value1","key2":"value2"})"
    };

    for (const auto& testData : testDataList) {
        PublishOption option;
        option.freq = LOW;
        option.capabilityData = reinterpret_cast<uint8_t *>(const_cast<char *>(testData.data()));
        option.dataLen = testData.length();
        SetCapBitMapPos(CAPABILITY_NUM, option.capabilityBitmap, CASTPLUS_CAPABILITY_BITMAP);

        EXPECT_EQ(g_interface->mediumInterface->Publish(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        EXPECT_EQ(g_interface->mediumInterface->Unpublish(&option), SOFTBUS_OK);
    }

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleCapabilityDataTest001 end ----");
}

/*
 * @tc.name: DiscBleSameAccountAndWakeRemote001
 * @tc.desc: test isSameAccount and isWakeRemote flags
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleSameAccountAndWakeRemote001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleSameAccountAndWakeRemote001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Test different combinations
    for (int32_t sameAccount = 0; sameAccount <= 1; sameAccount++) {
        for (int32_t wakeRemote = 0; wakeRemote <= 1; wakeRemote++) {
            SubscribeOption option = GetSubscribeOptionForCastPlus();
            option.isSameAccount = (sameAccount == 1);
            option.isWakeRemote = (wakeRemote == 1);

            EXPECT_EQ(g_interface->mediumInterface->Subscribe(&option), SOFTBUS_OK);
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option), SOFTBUS_OK);
        }
    }

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleSameAccountAndWakeRemote001 end ----");
}

/*
 * @tc.name: DiscBleMultiDeviceFound001
 * @tc.desc: test multiple device found callbacks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleMultiDeviceFound001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleMultiDeviceFound001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Start passive discovery
    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Inject multiple passive packets
    for (int32_t i = 0; i < 5; i++) {
        (void)memset_s(&g_foundDeviceInfo, sizeof(g_foundDeviceInfo), 0, sizeof(DeviceInfo));
        BleMock::InjectPassiveNonPacket();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        EXPECT_EQ(strcmp(g_foundDeviceInfo.devId, FOUND_DEVICE_ID), 0);
    }

    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleMultiDeviceFound001 end ----");
}

/*
 * @tc.name: DiscBleCustomDataParsing001
 * @tc.desc: test custom data parsing in device found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleCustomDataParsing001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleCustomDataParsing001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Subscribe and receive custom data packet
    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    BleMock::InjectPassiveNonPacketOfCust();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_EQ(strcmp(g_foundDeviceInfo.devId, FOUND_DEVICE_ID), 0);
    EXPECT_EQ(g_foundDeviceInfo.capabilityBitmap[0], 1 << CASTPLUS_CAPABILITY_BITMAP);

    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleCustomDataParsing001 end ----");
}

/*
 * @tc.name: DiscBleUpdateDeviceInfo001
 * @tc.desc: test device info update during runtime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleUpdateDeviceInfo001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUpdateDeviceInfo001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, UpdateBroadcasting(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForActiveDiscovery);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Start active discovery
    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Update device info
    ASSERT_NE(g_interface->mediumInterface->UpdateLocalDeviceInfo, nullptr);
    g_interface->mediumInterface->UpdateLocalDeviceInfo(TYPE_LOCAL_DEVICE_NAME);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleUpdateDeviceInfo001 end ----");
}

/*
 * @tc.name: DiscBleAllFrequenciesTest001
 * @tc.desc: test all frequency settings including SUPER_HIGH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleAllFrequenciesTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleAllFrequenciesTest001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Test all frequencies
    int32_t frequencies[] = {LOW, MID, HIGH, SUPER_HIGH};
    for (int32_t freq : frequencies) {
        PublishOption option;
        option.freq = freq;
        option.capabilityData = reinterpret_cast<uint8_t *>(g_customCapData.data());
        option.dataLen = g_customCapData.length();
        SetCapBitMapPos(CAPABILITY_NUM, option.capabilityBitmap, CASTPLUS_CAPABILITY_BITMAP);

        EXPECT_EQ(g_interface->mediumInterface->Publish(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        EXPECT_EQ(g_interface->mediumInterface->Unpublish(&option), SOFTBUS_OK);
    }

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleAllFrequenciesTest001 end ----");
}

/*
 * @tc.name: DiscBleActiveDiscoveryMultiple001
 * @tc.desc: test multiple active discovery operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleActiveDiscoveryMultiple001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleActiveDiscoveryMultiple001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Start multiple active discoveries
    SubscribeOption option1 = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option1), SOFTBUS_OK);

    SubscribeOption option2 = GetSubscribeOptionForOsd();
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option2), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Stop both
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option1), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option2), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleActiveDiscoveryMultiple001 end ----");
}

/*
 * @tc.name: DiscBlePassiveDiscoveryMultiple001
 * @tc.desc: test multiple passive discovery operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBlePassiveDiscoveryMultiple001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBlePassiveDiscoveryMultiple001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Start multiple passive discoveries
    SubscribeOption option1 = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&option1), SOFTBUS_OK);

    SubscribeOption option2 = GetSubscribeOptionForOsd();
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&option2), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Inject discovery packet
    BleMock::InjectActiveNonPacket();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Stop both
    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option1), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option2), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBlePassiveDiscoveryMultiple001 end ----");
}

/*
 * @tc.name: DiscBlePassivePublishMultiple001
 * @tc.desc: test multiple passive publish operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBlePassivePublishMultiple001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBlePassivePublishMultiple001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, UpdateBroadcasting(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForPassivePublish);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Start multiple passive publishes
    PublishOption option1 = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartScan(&option1), SOFTBUS_OK);

    PublishOption option2;
    option2.freq = LOW;
    option2.capabilityData = reinterpret_cast<uint8_t *>(g_customCapData.data());
    option2.dataLen = g_customCapData.length();
    SetCapBitMapPos(CAPABILITY_NUM, option2.capabilityBitmap, OSD_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->mediumInterface->StartScan(&option2), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Inject discovery packet
    BleMock::InjectActiveConPacket();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Stop both
    EXPECT_EQ(g_interface->mediumInterface->StopScan(&option1), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->StopScan(&option2), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBlePassivePublishMultiple001 end ----");
}

/*
 * @tc.name: DiscBleMixedOperations001
 * @tc.desc: test mixed active and passive operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleMixedOperations001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleMixedOperations001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, UpdateBroadcasting(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForPassivePublish);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Start active publish
    PublishOption pubOption = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Publish(&pubOption), SOFTBUS_OK);

    // Start passive discovery
    SubscribeOption subOption = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&subOption), SOFTBUS_OK);

    // Start active discovery
    SubscribeOption advOption = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&advOption), SOFTBUS_OK);

    // Start passive publish
    PublishOption scanOption;
    scanOption.freq = LOW;
    scanOption.capabilityData = reinterpret_cast<uint8_t *>(g_customCapData.data());
    scanOption.dataLen = g_customCapData.length();
    SetCapBitMapPos(CAPABILITY_NUM, scanOption.capabilityBitmap, OSD_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->mediumInterface->StartScan(&scanOption), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    // Stop all
    EXPECT_EQ(g_interface->mediumInterface->Unpublish(&pubOption), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&subOption), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&advOption), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->StopScan(&scanOption), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleMixedOperations001 end ----");
}

/*
 * @tc.name: DiscBleRapidSwitch001
 * @tc.desc: test rapid switching between different operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleRapidSwitch001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleRapidSwitch001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    PublishOption option = GetPublishOptionForCastPlus();

    // Rapid publish/unpublish
    for (int32_t i = 0; i < 5; i++) {
        EXPECT_EQ(g_interface->mediumInterface->Publish(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        EXPECT_EQ(g_interface->mediumInterface->Unpublish(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleRapidSwitch001 end ----");
}

/*
 * @tc.name: DiscBleLongRunningOperation001
 * @tc.desc: test long running operation stability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleLongRunningOperation001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleLongRunningOperation001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Start long running subscribe
    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&option), SOFTBUS_OK);

    // Inject multiple packets over time
    for (int32_t i = 0; i < 5; i++) {
        (void)memset_s(&g_foundDeviceInfo, sizeof(g_foundDeviceInfo), 0, sizeof(DeviceInfo));
        BleMock::InjectActiveNonPacket();
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleLongRunningOperation001 end ----");
}

/*
 * @tc.name: DiscBleDeviceFoundWithRefreshData001
 * @tc.desc: test device found with refresh data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleDeviceFoundWithRefreshData001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleDeviceFoundWithRefreshData001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Subscribe with valid refresh data
    SubscribeOption option = GetSubscribeOptionForCastPlusGetHandle(validRefreshData);
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);

    // Subscribe with invalid refresh data
    SubscribeOption option2 = GetSubscribeOptionForCastPlusGetHandle(invalidRefreshData);
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option2), SOFTBUS_INVALID_PARAM);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleDeviceFoundWithRefreshData001 end ----");
}

/*
 * @tc.name: DiscBleCapabilityBitmapAll001
 * @tc.desc: test all supported capability bitmaps
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleCapabilityBitmapAll001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleCapabilityBitmapAll001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Test CastPlus
    uint32_t capability1 = 0;
    SetCapBitMapPos(1, &capability1, CASTPLUS_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->IsConcern(capability1), true);

    // Test DVKit
    uint32_t capability2 = 0;
    SetCapBitMapPos(1, &capability2, DVKIT_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->IsConcern(capability2), true);

    // Test OSD
    uint32_t capability3 = 0;
    SetCapBitMapPos(1, &capability3, OSD_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->IsConcern(capability3), true);

    // Test SHARE (should be false)
    uint32_t capability4 = 0;
    SetCapBitMapPos(1, &capability4, SHARE_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->IsConcern(capability4), false);

    // Test multiple capabilities
    uint32_t capability5 = 0;
    SetCapBitMapPos(1, &capability5, CASTPLUS_CAPABILITY_BITMAP);
    SetCapBitMapPos(1, &capability5, DVKIT_CAPABILITY_BITMAP);
    EXPECT_EQ(g_interface->IsConcern(capability5), true);

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleCapabilityBitmapAll001 end ----");
}

/*
 * @tc.name: DiscBleMemoryPressure001
 * @tc.desc: test behavior under memory pressure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleMemoryPressure001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleMemoryPressure001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Create multiple operations to simulate memory pressure
    std::vector<SubscribeOption> options;
    for (int32_t i = 0; i < 10; i++) {
        SubscribeOption option;
        option.freq = LOW;
        option.isSameAccount = false;
        option.isWakeRemote = false;
        option.capabilityData = reinterpret_cast<uint8_t *>(g_customCapData.data());
        option.dataLen = g_customCapData.length();
        SetCapBitMapPos(CAPABILITY_NUM, option.capabilityBitmap, CASTPLUS_CAPABILITY_BITMAP);

        options.push_back(option);
        EXPECT_EQ(g_interface->mediumInterface->Subscribe(&option), SOFTBUS_OK);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Clean up all
    for (auto& option : options) {
        EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option), SOFTBUS_OK);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleMemoryPressure001 end ----");
}

/*
 * @tc.name: DiscBleConcurrentStartStop001
 * @tc.desc: test concurrent start and stop operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleConcurrentStartStop001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleConcurrentStartStop001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Start multiple operations concurrently
    PublishOption pubOption1 = GetPublishOptionForCastPlus();
    PublishOption pubOption2;
    pubOption2.freq = MID;
    pubOption2.capabilityData = reinterpret_cast<uint8_t *>(g_customCapData.data());
    pubOption2.dataLen = g_customCapData.length();
    SetCapBitMapPos(CAPABILITY_NUM, pubOption2.capabilityBitmap, DVKIT_CAPABILITY_BITMAP);

    SubscribeOption subOption1 = GetSubscribeOptionForCastPlus();
    SubscribeOption subOption2 = GetSubscribeOptionForOsd();

    EXPECT_EQ(g_interface->mediumInterface->Publish(&pubOption1), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->Publish(&pubOption2), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&subOption1), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&subOption2), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Stop all
    EXPECT_EQ(g_interface->mediumInterface->Unpublish(&pubOption1), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->Unpublish(&pubOption2), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&subOption1), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&subOption2), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleConcurrentStartStop001 end ----");
}

/*
 * @tc.name: DiscBleBtToggleDuringDiscovery001
 * @tc.desc: test BT toggle during active discovery
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleBtToggleDuringDiscovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleBtToggleDuringDiscovery001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Toggle BT multiple times
    for (int32_t i = 0; i < 3; i++) {
        BleMock::TurnOffBt();
        EXPECT_EQ(bleMock.IsScanning(), false);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        BleMock::TurnOnBt();
        EXPECT_EQ(bleMock.IsScanning(), true);

        // Re-setup BusCenterMock after BT toggle
        busMock.SetupSuccessStub();

        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }

    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    // Use longer wait time (2000ms) for BT state toggle test cases
    BleMock::WaitForBleMockSafeDestruction(2000);
    DISC_LOGI(DISC_TEST, "DiscBleBtToggleDuringDiscovery001 end ----");
}

/*
 * @tc.name: DiscBleDeviceInfoUpdateMultiple001
 * @tc.desc: test multiple device info updates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleDeviceInfoUpdateMultiple001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleDeviceInfoUpdateMultiple001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, UpdateBroadcasting(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForActiveDiscovery);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Multiple updates
    ASSERT_NE(g_interface->mediumInterface->UpdateLocalDeviceInfo, nullptr);
    for (int32_t i = 0; i < 5; i++) {
        g_interface->mediumInterface->UpdateLocalDeviceInfo(TYPE_LOCAL_DEVICE_NAME);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }

    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleDeviceInfoUpdateMultiple001 end ----");
}

/*
 * @tc.name: DiscBleScanWithActiveConPacket001
 * @tc.desc: test scan functionality with active con packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleScanWithActiveConPacket001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleScanWithActiveConPacket001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, UpdateBroadcasting(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForPassivePublish);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    PublishOption option = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartScan(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Inject active con packet
    BleMock::InjectActiveConPacket();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    EXPECT_EQ(g_interface->mediumInterface->StopScan(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleScanWithActiveConPacket001 end ----");
}

/*
 * @tc.name: DiscBlePassiveWithDisplayName001
 * @tc.desc: test passive discovery with display name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBlePassiveWithDisplayName001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBlePassiveWithDisplayName001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, UpdateBroadcasting(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForActiveDiscovery);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Set display name
    const char *pkgName = "ohos.distributedhardware.devicemanager";
    const char *nameData = "{\"raw\": \"My Device\",\"name18\": \"Display Name 18\","
        "\"name21\": \"Display Name 21\",\"name24\": \"Display Name 24\"}";
    DiscSetDisplayName(pkgName, nameData, strlen(nameData));

    // Start passive discovery with OSD
    SubscribeOption option = GetSubscribeOptionForOsd();
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBlePassiveWithDisplayName001 end ----");
}

/*
 * @tc.name: DiscBleAllPublishTypes001
 * @tc.desc: test all types of publish operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleAllPublishTypes001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleAllPublishTypes001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, UpdateBroadcasting(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForPassivePublish);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Test active publish
    PublishOption activePub = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Publish(&activePub), SOFTBUS_OK);
    EXPECT_EQ(bleMock.GetAsyncAdvertiseResult(), true);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_interface->mediumInterface->Unpublish(&activePub), SOFTBUS_OK);

    // Test passive publish
    PublishOption passivePub = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartScan(&passivePub), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_interface->mediumInterface->StopScan(&passivePub), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleAllPublishTypes001 end ----");
}

/*
 * @tc.name: DiscBleAllDiscoveryTypes001
 * @tc.desc: test all types of discovery operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleAllDiscoveryTypes001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleAllDiscoveryTypes001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Test active discovery
    SubscribeOption activeDisc = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&activeDisc), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&activeDisc), SOFTBUS_OK);

    // Test passive discovery
    SubscribeOption passiveDisc = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&passiveDisc), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&passiveDisc), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleAllDiscoveryTypes001 end ----");
}

/*
 * @tc.name: DiscBleErrorRecovery001
 * @tc.desc: test error recovery after BT off
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleErrorRecovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleErrorRecovery001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Start operation
    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Turn off BT
    BleMock::TurnOffBt();
    EXPECT_EQ(bleMock.IsScanning(), false);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Turn on BT - should recover
    BleMock::TurnOnBt();
    EXPECT_EQ(bleMock.IsScanning(), true);

    // Re-setup BusCenterMock after BT toggle
    busMock.SetupSuccessStub();

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    // Use longer wait time (2000ms) for BT state toggle test cases
    BleMock::WaitForBleMockSafeDestruction(2000);
    DISC_LOGI(DISC_TEST, "DiscBleErrorRecovery001 end ----");
}

/*
 * @tc.name: DiscBleDifferentCapabilityData001
 * @tc.desc: test with different capability data formats
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleDifferentCapabilityData001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleDifferentCapabilityData001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Test various data formats
    std::vector<std::string> dataFormats = {
        R"({"simple":"data"})",
        R"({"castPlus":"1122","extCustData":"1122"})",
        R"({"key1":"value1","key2":"value2","key3":"value3"})",
        R"({"longData":"This is a longer data string for testing"})",
        R"({"num":123,"bool":true,"null":null})",
        R"({"nested":{"key":"value"}})",
        R"({"array":[1,2,3]})"
    };

    for (const auto& data : dataFormats) {
        PublishOption option;
        option.freq = LOW;
        option.capabilityData = reinterpret_cast<uint8_t *>(const_cast<char *>(data.data()));
        option.dataLen = data.length();
        SetCapBitMapPos(CAPABILITY_NUM, option.capabilityBitmap, CASTPLUS_CAPABILITY_BITMAP);

        EXPECT_EQ(g_interface->mediumInterface->Publish(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        EXPECT_EQ(g_interface->mediumInterface->Unpublish(&option), SOFTBUS_OK);
    }

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleDifferentCapabilityData001 end ----");
}

/*
 * @tc.name: DiscBleSubscribeUnsubscribeMultiple001
 * @tc.desc: test multiple subscribe/unsubscribe cycles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleSubscribeUnsubscribeMultiple001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleSubscribeUnsubscribeMultiple001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    SubscribeOption option = GetSubscribeOptionForCastPlus();

    // Multiple subscribe/unsubscribe cycles
    for (int32_t i = 0; i < 5; i++) {
        EXPECT_EQ(g_interface->mediumInterface->Subscribe(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleSubscribeUnsubscribeMultiple001 end ----");
}

/*
 * @tc.name: DiscBlePublishUnpublishMultiple001
 * @tc.desc: test multiple publish/unpublish cycles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBlePublishUnpublishMultiple001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBlePublishUnpublishMultiple001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    PublishOption option = GetPublishOptionForCastPlus();

    // Multiple publish/unpublish cycles
    for (int32_t i = 0; i < 5; i++) {
        EXPECT_EQ(g_interface->mediumInterface->Publish(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        EXPECT_EQ(g_interface->mediumInterface->Unpublish(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBlePublishUnpublishMultiple001 end ----");
}

/*
 * @tc.name: DiscBleStartAdvertiseStopAdvertiseMultiple001
 * @tc.desc: test multiple start/stop advertise cycles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleStartAdvertiseStopAdvertiseMultiple001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleStartAdvertiseStopAdvertiseMultiple001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    SubscribeOption option = GetSubscribeOptionForCastPlus();

    // Multiple start/stop advertise cycles
    for (int32_t i = 0; i < 5; i++) {
        EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleStartAdvertiseStopAdvertiseMultiple001 end ----");
}

/*
 * @tc.name: DiscBleStartScanStopScanMultiple001
 * @tc.desc: test multiple start/stop scan cycles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleStartScanStopScanMultiple001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleStartScanStopScanMultiple001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, UpdateBroadcasting(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForPassivePublish);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    PublishOption option = GetPublishOptionForCastPlus();

    // Multiple start/stop scan cycles
    for (int32_t i = 0; i < 5; i++) {
        EXPECT_EQ(g_interface->mediumInterface->StartScan(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        EXPECT_EQ(g_interface->mediumInterface->StopScan(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleStartScanStopScanMultiple001 end ----");
}

/*
 * @tc.name: DiscBleAllCapabilitiesCombo001
 * @tc.desc: test all capability combinations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleAllCapabilitiesCombo001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleAllCapabilitiesCombo001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Test each capability individually
    std::vector<int32_t> capabilities = {
        CASTPLUS_CAPABILITY_BITMAP,
        DVKIT_CAPABILITY_BITMAP,
        OSD_CAPABILITY_BITMAP
    };

    for (auto cap : capabilities) {
        PublishOption option;
        option.freq = LOW;
        option.capabilityData = reinterpret_cast<uint8_t *>(g_customCapData.data());
        option.dataLen = g_customCapData.length();
        SetCapBitMapPos(CAPABILITY_NUM, option.capabilityBitmap, cap);

        EXPECT_EQ(g_interface->mediumInterface->Publish(&option), SOFTBUS_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        EXPECT_EQ(g_interface->mediumInterface->Unpublish(&option), SOFTBUS_OK);
    }

    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleAllCapabilitiesCombo001 end ----");
}

/*
 * @tc.name: DiscBleDeviceFoundCallbackVerification001
 * @tc.desc: test device found callback verification
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleDeviceFoundCallbackVerification001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleDeviceFoundCallbackVerification001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Subscribe
    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Clear device info
    (void)memset_s(&g_foundDeviceInfo, sizeof(g_foundDeviceInfo), 0, sizeof(DeviceInfo));

    // Inject packet and verify callback
    BleMock::InjectActiveNonPacket();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Verify callback was called with correct data
    EXPECT_EQ(strcmp(g_foundDeviceInfo.devId, FOUND_DEVICE_ID), 0);
    EXPECT_EQ(g_foundDeviceInfo.capabilityBitmap[0], 1 << CASTPLUS_CAPABILITY_BITMAP);

    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleDeviceFoundCallbackVerification001 end ----");
}

/*
 * @tc.name: DiscBleAsyncOperationSafety001
 * @tc.desc: test async operation safety
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleAsyncOperationSafety001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleAsyncOperationSafety001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::TurnOnBt();

    // Start multiple async operations
    PublishOption pubOption = GetPublishOptionForCastPlus();
    SubscribeOption subOption = GetSubscribeOptionForCastPlus();

    EXPECT_EQ(g_interface->mediumInterface->Publish(&pubOption), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&subOption), SOFTBUS_OK);

    // Don't wait - immediately stop
    EXPECT_EQ(g_interface->mediumInterface->Unpublish(&pubOption), SOFTBUS_OK);
    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&subOption), SOFTBUS_OK);

    // Wait for async operations to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    BleMock::TurnOffBt();
    // Wait for BleMock and BusCenterMock async operations to complete before mock destructors
    BleMock::WaitForBleMockSafeDestruction();
    DISC_LOGI(DISC_TEST, "DiscBleAsyncOperationSafety001 end ----");
}

/*
 * @tc.name: DiscBleDeInit001
 * @tc.desc: stop passive publish successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBleTest, DiscBleDeInit001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleDeInit001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::WaitRecvMessageObsolete();
    DiscSoftBusBleDeinit();
    EXPECT_EQ(BleMock::IsDeInitSuccess(), true);
    DISC_LOGI(DISC_TEST, "DiscBleDeInit001 end ----");
}
} // namespace OHOS