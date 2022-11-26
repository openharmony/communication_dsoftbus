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

#include <fstream>
#include <thread>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "disc_ble.h"
#include "disc_ble_utils.h"
#include "bus_center_mock.h"
#include "ble_mock.h"
#include "message_handler.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "securec.h"
#include "exception_branch_checker.h"

using namespace testing::ext;
using testing::Return;
using testing::_;
using testing::NotNull;
using testing::NiceMock;

namespace OHOS {
class DiscBleMockTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        LooperInit();
    }

    static void TearDownTestCase()
    {
        LooperDeinit();
    }

    void SetUp() override {}
    void TearDown() override {}

    static inline std::string g_customCapData = "name=Bill";
    static inline DeviceInfo g_foundDeviceInfo;
    static constexpr char FOUND_DEVICE_ID[] = "d01559bb";
};

static void OnDeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions)
{
    DLOGI("OnDeviceFound: %s", device->devId);
    DiscBleMockTest::g_foundDeviceInfo = *device;
}

static DiscInnerCallback g_discInnerCallback = {
    .OnDeviceFound = OnDeviceFound,
};

static DiscoveryBleDispatcherInterface *g_interface;

static PublishOption GetPublishOptionForCastPlus()
{
    PublishOption option {};
    option.freq = LOW;
    option.capabilityData = reinterpret_cast<uint8_t *>(DiscBleMockTest::g_customCapData.data());
    option.dataLen = DiscBleMockTest::g_customCapData.length();

    SetCapBitMapPos(CAPABILITY_NUM, option.capabilityBitmap, CASTPLUS_CAPABILITY_BITMAP);
    return option;
}

static SubscribeOption GetSubscribeOptionForCastPlus()
{
    SubscribeOption option {};
    option.freq = LOW;
    option.isSameAccount = false;
    option.isWakeRemote = false;
    option.capabilityData = reinterpret_cast<uint8_t *>(DiscBleMockTest::g_customCapData.data());
    option.dataLen = DiscBleMockTest::g_customCapData.length();

    SetCapBitMapPos(CAPABILITY_NUM, option.capabilityBitmap, CASTPLUS_CAPABILITY_BITMAP);
    return option;
}

static SubscribeOption GetSubscribeOptionForOsd()
{
    SubscribeOption option {};
    option.freq = LOW;
    option.isSameAccount = false;
    option.isWakeRemote = false;
    option.capabilityData = reinterpret_cast<uint8_t *>(DiscBleMockTest::g_customCapData.data());
    option.dataLen = DiscBleMockTest::g_customCapData.length();

    SetCapBitMapPos(CAPABILITY_NUM, option.capabilityBitmap, OSD_CAPABILITY_BITMAP);
    return option;
}

/*
* @tc.name: DiscBleInit001
* @tc.desc: invalid input parameter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, DiscBleInit001, TestSize.Level1)
{
    DLOGI("DiscBleInit001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    EXPECT_EQ(DiscSoftBusBleInit(nullptr), nullptr);

    ExceptionBranchChecker checker("callback invalid");
    DiscInnerCallback callback;
    callback.OnDeviceFound = nullptr;
    EXPECT_EQ(DiscSoftBusBleInit(&callback), nullptr);
    EXPECT_EQ(checker.GetResult(), true);
    DLOGI("DiscBleInit001 end ----");
}

/*
* @tc.name: DiscBleInit002
* @tc.desc: scan listener init failed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, DiscBleInit002, TestSize.Level1)
{
    DLOGI("DiscBleInit002 begin ----");
    {
        BleMock bleMock;
        bleMock.SetupSuccessStub();
        EXPECT_CALL(bleMock, SoftBusAddScanListener).WillRepeatedly(Return(SOFTBUS_ERR));

        EXPECT_EQ(DiscSoftBusBleInit(&g_discInnerCallback), nullptr);
    }
    {
        BleMock bleMock;
        bleMock.SetupSuccessStub();
        EXPECT_CALL(bleMock, SoftBusAddBtStateListener).WillRepeatedly(Return(SOFTBUS_ERR));

        EXPECT_EQ(DiscSoftBusBleInit(&g_discInnerCallback), nullptr);
    }
    {
        BleMock bleMock;
        bleMock.SetupSuccessStub();
        EXPECT_CALL(bleMock, SoftBusGetAdvChannel).WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_ERR));

        EXPECT_EQ(DiscSoftBusBleInit(&g_discInnerCallback), nullptr);
    }
    {
        BleMock bleMock;
        bleMock.SetupSuccessStub();
        EXPECT_CALL(bleMock, SoftBusGetAdvChannel).WillOnce(Return(SOFTBUS_ERR)).WillOnce(Return(SOFTBUS_OK));

        EXPECT_EQ(DiscSoftBusBleInit(&g_discInnerCallback), nullptr);
    }
    {
        BleMock bleMock;
        bleMock.SetupSuccessStub();
        EXPECT_CALL(bleMock, SoftBusSetScanFilter).WillOnce(Return(SOFTBUS_ERR));

        EXPECT_NE(DiscSoftBusBleInit(&g_discInnerCallback), nullptr);
    }
    DLOGI("DiscBleInit002 end ----");
}

/*
* @tc.name: DiscBleInit003
* @tc.desc: valid parameter, init successful
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, DiscBleInit003, TestSize.Level1)
{
    DLOGI("DiscBleInit003 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    g_interface = DiscSoftBusBleInit(&g_discInnerCallback);
    EXPECT_NE(g_interface, nullptr);
    DLOGI("DiscBleInit003 end ----");
}

/*
* @tc.name: StartActiveDiscovery001
* @tc.desc: start active discovery successfully
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, StartActiveDiscovery001, TestSize.Level1)
{
    DLOGI("StartActiveDiscovery001 begin ----");
    NiceMock<BleMock> bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, SoftBusSetAdvData(_, NotNull())).WillRepeatedly(BleMock::ActionOfSetAdvDataForActiveDiscovery);

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

    DLOGI("StartActiveDiscovery001 end ----");
}

/*
* @tc.name: StartActiveDiscovery002
* @tc.desc: start the second capability to update advertiser
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, StartActiveDiscovery002, TestSize.Level1)
{
    DLOGI("StartActiveDiscovery002 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, SoftBusUpdateAdv(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForActiveDiscovery);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    SubscribeOption option = GetSubscribeOptionForOsd();
    EXPECT_EQ(g_interface->mediumInterface->StartAdvertise(&option), SOFTBUS_OK);
    EXPECT_EQ(bleMock.GetAsyncAdvertiseResult(), true);

    DLOGI("StartActiveDiscovery002 end ----");
}

/*
* @tc.name: UpdateLocalDeviceInfo001
* @tc.desc: update local device info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, UpdateLocalDeviceInfo001, TestSize.Level1)
{
    DLOGI("UpdateLocalDeviceInfo001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, SoftBusUpdateAdv(_, NotNull(), NotNull()))
        .WillRepeatedly(BleMock::ActionOfUpdateAdvForActiveDiscovery);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    ExceptionBranchChecker checker("update success");
    g_interface->mediumInterface->UpdateLocalDeviceInfo(TYPE_LOCAL_DEVICE_NAME);
    EXPECT_EQ(checker.GetResult(), true);

    DLOGI("UpdateLocalDeviceInfo001 end ----");
}

/*
* @tc.name: ReceivePassivePublishPacket001
* @tc.desc: receive passive publish packet
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, ReceivePassivePublishPacket001, TestSize.Level1)
{
    DLOGI("ReceivePassivePublishPacket001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::InjectPassiveNonPacket();

    EXPECT_EQ(strcmp(g_foundDeviceInfo.devId, FOUND_DEVICE_ID), 0);
    EXPECT_EQ(g_foundDeviceInfo.capabilityBitmap[0], 1 << CASTPLUS_CAPABILITY_BITMAP);
    (void)memset_s(&g_foundDeviceInfo, sizeof(g_foundDeviceInfo), 0, sizeof(DeviceInfo));
    DLOGI("ReceivePassivePublishPacket001 end ----");
}

/*
* @tc.name: StopActiveDiscovery001
* @tc.desc: stop active discovery successfully
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, StopActiveDiscovery001, TestSize.Level1)
{
    DLOGI("StopActiveDiscovery001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);
    option = GetSubscribeOptionForOsd();
    EXPECT_EQ(g_interface->mediumInterface->StopAdvertise(&option), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    DLOGI("StopActiveDiscovery001 end ----");
}

/*
* @tc.name: StartActiveDiscovery001
* @tc.desc: start active discovery successfully
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, StartPassiveDiscovery001, TestSize.Level1)
{
    DLOGI("StartPassiveDiscovery001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Subscribe(&option), SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    BleMock::InjectActiveNonPacket();
    std::this_thread::sleep_for(std::chrono::seconds(1));

    EXPECT_EQ(strcmp(g_foundDeviceInfo.devId, FOUND_DEVICE_ID), 0);
    EXPECT_EQ(g_foundDeviceInfo.capabilityBitmap[0], 1 << CASTPLUS_CAPABILITY_BITMAP);
    (void)memset_s(&g_foundDeviceInfo, sizeof(g_foundDeviceInfo), 0, sizeof(DeviceInfo));
    DLOGI("StartPassiveDiscovery001 end ----");
}

/*
* @tc.name: StopPassiveDiscovery001
* @tc.desc: stop active discovery successfully
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, StopPassiveDiscovery001, TestSize.Level1)
{
    DLOGI("StopPassiveDiscovery001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    SubscribeOption option = GetSubscribeOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option), SOFTBUS_OK);

    option = GetSubscribeOptionForOsd();
    EXPECT_EQ(g_interface->mediumInterface->Unsubscribe(&option), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    DLOGI("StopPassiveDiscovery001 end ----");
}

/*
* @tc.name: StartActivePublish001
* @tc.desc: start active publish successfully
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, StartActivePublish001, TestSize.Level1)
{
    DLOGI("StartActivePublish001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, SoftBusSetAdvData(_, NotNull())).WillRepeatedly(BleMock::ActionOfSetAdvDataForActivePublish);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    PublishOption option = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Publish(&option), SOFTBUS_OK);
    EXPECT_EQ(bleMock.GetAsyncAdvertiseResult(), true);

    DLOGI("StartActivePublish001 end ----");
}

/*
* @tc.name: StopActivePublish001
* @tc.desc: stop active publish successfully
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, StopActivePublish001, TestSize.Level1)
{
    DLOGI("StopActivePublish001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    PublishOption option = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->Unpublish(&option), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    DLOGI("StopActivePublish001 end ----");
}

/*
* @tc.name: StartPassivePublish001
* @tc.desc: start passive publish successfully
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, StartPassivePublish001, TestSize.Level1)
{
    DLOGI("StartPassivePublish001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    PublishOption option = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StartScan(&option), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    DLOGI("StartPassivePublish001 end ----");
}

/*
* @tc.name: ReceiveActiveDiscoveryPacket001
* @tc.desc: when receiving active discovery packet, handle it successfully
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, ReceiveActiveDiscoveryPacket001, TestSize.Level1)
{
    DLOGI("ReceiveActiveDiscoveryPacket001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();
    EXPECT_CALL(bleMock, SoftBusSetAdvData(_, NotNull()))
        .WillRepeatedly(BleMock::ActionOfSetAdvDataForPassivePublish);

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::InjectActiveConPacket();
    EXPECT_EQ(bleMock.GetAsyncAdvertiseResult(), true);

    BleMock::InjectActiveConPacket();
    DLOGI("ReceiveActiveDiscoveryPacket001 end ----");
}

/*
* @tc.name: StopPassivePublish001
* @tc.desc: stop passive publish successfully
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, StopPassivePublish001, TestSize.Level1)
{
    DLOGI("StopPassivePublish001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    PublishOption option = GetPublishOptionForCastPlus();
    EXPECT_EQ(g_interface->mediumInterface->StopScan(&option), SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    DLOGI("StopPassivePublish001 end ----");
}

/*
* @tc.name: IsConcernCapability001
* @tc.desc: test ble discovery supported capability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, IsConcernCapability001, TestSize.Level1)
{
    DLOGI("IsConcernCapability001 begin ----");
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
    DLOGI("IsConcernCapability001 end ----");
}

/*
* @tc.name: DiscBleDeInit001
* @tc.desc: stop passive publish successfully
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscBleMockTest, DiscBleDeInit001, TestSize.Level1)
{
    DLOGI("DiscBleDeInit001 begin ----");
    BleMock bleMock;
    bleMock.SetupSuccessStub();

    BusCenterMock busMock;
    busMock.SetupSuccessStub();

    BleMock::WaitRecvMessageObsolete();
    DiscSoftBusBleDeinit();
    EXPECT_EQ(BleMock::IsDeInitSuccess(), true);
    DLOGI("DiscBleDeInit001 end ----");
}
}