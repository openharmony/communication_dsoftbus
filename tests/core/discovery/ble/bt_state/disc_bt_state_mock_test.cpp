/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>

#include "bluetooth_mock.h"
#include "disc_ble.h"
#include "disc_log.h"
#include "lnn_local_net_ledger.h"
#include "message_handler.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace {
constexpr int64_t SLEEP_TIME = 200;
const std::string PACKET_CON = "0201021B16EEFD0405900000020018DD61155F421C49DA210E3C4F70656E480AFF7D0261726D6F6E7900";
const std::string PACKET_NON = "0201021B16EEFD0405100000020018DD61155F421C49DA210E3C4F70656E480AFF7D0261726D6F6E7900";
const std::string PACKET_NON_WITH_BR_ADDR =
    "0201021B16EEFD0405100000020018DD61155F421C49DA210E56012345678911FF7D02AB3C4F70656E4861726D6F6E7900";
const std::string CAST_PUBLISH_CAPA_DATA = R"({"castPlus":"AA00"})";
const std::string CAST_REFRESH_CAPA_DATA = R"({"castPlus":"AA00"})";
constexpr int32_t CAST_CAPABILITY = 1 << CASTPLUS_CAPABILITY_BITMAP;
const PublishOption g_publishOption = {
    .freq = MID,
    .capabilityBitmap = { CAST_CAPABILITY },
    .capabilityData = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(CAST_PUBLISH_CAPA_DATA.c_str())),
    .dataLen = static_cast<uint32_t>(CAST_PUBLISH_CAPA_DATA.length()),
};
const SubscribeOption g_subscribeOption = {
    .freq = MID,
    .isSameAccount = false,
    .isWakeRemote = false,
    .capabilityBitmap = { CAST_CAPABILITY },
    .capabilityData = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(CAST_REFRESH_CAPA_DATA.c_str())),
    .dataLen = static_cast<uint32_t>(CAST_REFRESH_CAPA_DATA.length()),
};

bool g_isDeviceFound = false;

void OnDeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    ASSERT_NE(device, nullptr);
    ASSERT_NE(additions, nullptr);

    g_isDeviceFound = true;
    std::stringstream ss;
    ss << "OnDeviceFound medium=" << additions->medium << ", name=" << device->devName;
    ss << ", cap=" << device->capabilityBitmap[0] << ", cust=" << device->custData;
    for (uint32_t addrIndex = 0; addrIndex < device->addrNum; ++addrIndex) {
        if (device->addr[addrIndex].type == CONNECTION_ADDR_BR) {
            ss << ", brAddr=" << device->addr[addrIndex].info.br.brMac;
        } else if (device->addr[addrIndex].type == CONNECTION_ADDR_BLE) {
            ss << ", bleAddr=" << device->addr[addrIndex].info.ble.bleMac;
        }
    }
    printf("%s\n", ss.str().c_str());
}

DiscInnerCallback g_discInnerCallback = {
    .OnDeviceFound = OnDeviceFound,
};

void AssertInterfaceIsNotNull(const DiscoveryBleDispatcherInterface *interface)
{
    ASSERT_NE(interface, nullptr);
    ASSERT_NE(interface->mediumInterface, nullptr);
    ASSERT_NE(interface->mediumInterface->Publish, nullptr);
    ASSERT_NE(interface->mediumInterface->Unpublish, nullptr);
    ASSERT_NE(interface->mediumInterface->StartScan, nullptr);
    ASSERT_NE(interface->mediumInterface->StopScan, nullptr);
    ASSERT_NE(interface->mediumInterface->StartAdvertise, nullptr);
    ASSERT_NE(interface->mediumInterface->StopAdvertise, nullptr);
    ASSERT_NE(interface->mediumInterface->Subscribe, nullptr);
    ASSERT_NE(interface->mediumInterface->Unsubscribe, nullptr);
}
} // anonymous namespace

namespace OHOS {
using namespace testing::ext;
using testing::NiceMock;
using CMD = ExpectWrapper::ExpectCommand;

class DiscBtStateTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    void SetUp() override
    {
        LooperInit();
        LnnInitLocalLedger();
    }

    void TearDown() override
    {
        LnnDeinitLocalLedger();
        LooperDeinit();
    }
};

/*
 * @tc.name: SoftBusGetBtState001
 * @tc.desc: bluetooth state convert: OFF->ON, ON->OFF
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, SoftBusGetBtState001, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_OFF);
    // OFF -> ON
    {
        EXPECT_CALL(mock, EnableBle).Times(1);
        EXPECT_CALL(mock, EnableBr).Times(1);
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_ON);
        EXPECT_EQ(SoftBusGetBtState(), BLE_ENABLE);
        EXPECT_EQ(SoftBusGetBrState(), BR_ENABLE);
    }
    // ON -> OFF
    {
        EXPECT_CALL(mock, DisableBle).Times(1);
        EXPECT_CALL(mock, DisableBr).Times(1);
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_OFF);
        EXPECT_EQ(SoftBusGetBtState(), BLE_DISABLE);
        EXPECT_EQ(SoftBusGetBrState(), BR_DISABLE);
    }
}

/*
 * @tc.name: SoftBusGetBtState002
 * @tc.desc: bluetooth state convert: ON->RESTRICT, RESTRICT->OFF
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, SoftBusGetBtState002, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_ON);
    // ON -> RESTRICT
    {
        EXPECT_CALL(mock, DisableBr).Times(1);
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_RESTRICT);
        EXPECT_EQ(SoftBusGetBtState(), BLE_ENABLE);
        EXPECT_EQ(SoftBusGetBrState(), BR_DISABLE);
    }
    // RESTRICT -> OFF
    {
        EXPECT_CALL(mock, DisableBle).Times(1);
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_OFF);
        EXPECT_EQ(SoftBusGetBtState(), BLE_DISABLE);
        EXPECT_EQ(SoftBusGetBrState(), BR_DISABLE);
    }
}

/*
 * @tc.name: SoftBusGetBtState003
 * @tc.desc: bluetooth state convert: ON->RESTRICT, RESTRICT->ON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, SoftBusGetBtState003, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_ON);
    // ON -> RESTRICT
    {
        EXPECT_CALL(mock, DisableBr).Times(1);
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_RESTRICT);
        EXPECT_EQ(SoftBusGetBtState(), BLE_ENABLE);
        EXPECT_EQ(SoftBusGetBrState(), BR_DISABLE);
    }
    // RESTRICT -> ON
    {
        EXPECT_CALL(mock, EnableBr).Times(1);
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_ON);
        EXPECT_EQ(SoftBusGetBtState(), BLE_ENABLE);
        EXPECT_EQ(SoftBusGetBrState(), BR_ENABLE);
    }
}

/*
 * @tc.name: RefreshActive001
 * @tc.desc: should start adv CON without br addr, start scan when START_ACTIVE_DISCOVERY with br & ble enable
 *           should do nothing when recv CON packet
 *           should report device found when recv NON packet
 *           should stop scan when STOP_DISCOVERY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, RefreshActive001, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_ON);
    ExpectWrapper wrapper(mock);

    DiscoveryBleDispatcherInterface *interface = DiscSoftBusBleInit(&g_discInnerCallback);
    AssertInterfaceIsNotNull(interface);
    SoftBusBtInit();
    int32_t ret = SOFTBUS_OK;
    {
        wrapper.Call(CMD::BLE_START_SCAN_EX, 1).Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 0).Build();
        ret = interface->mediumInterface->StartAdvertise(&g_subscribeOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
        mock.CallbackAdvEnable();
    }
    {
        wrapper.Build(); // do nothing
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_CON);
        EXPECT_FALSE(g_isDeviceFound);
    }
    {
        wrapper.Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_NON);
        EXPECT_TRUE(g_isDeviceFound);
    }
    {
        wrapper.Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_NON_WITH_BR_ADDR);
        EXPECT_TRUE(g_isDeviceFound);
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Call(CMD::BLE_STOP_SCAN, 1).Build();
        ret = interface->mediumInterface->StopAdvertise(&g_subscribeOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    DiscSoftBusBleDeinit();
}

/*
 * @tc.name: RefreshPassive001
 * @tc.desc: should start scan when START_PASSIVE_DISCOVERY with br & ble enable
 *           should do nothing when recv CON packet
 *           should report device found when recv NON packet
 *           should stop scan when STOP_DISCOVERY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, RefreshPassive001, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_ON);
    ExpectWrapper wrapper(mock);

    DiscoveryBleDispatcherInterface *interface = DiscSoftBusBleInit(&g_discInnerCallback);
    AssertInterfaceIsNotNull(interface);
    SoftBusBtInit();
    int32_t ret = SOFTBUS_OK;
    {
        wrapper.Call(CMD::BLE_START_SCAN_EX, 1).Build();
        ret = interface->mediumInterface->Subscribe(&g_subscribeOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
        mock.CallbackAdvEnable();
    }
    {
        wrapper.Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_CON);
        EXPECT_FALSE(g_isDeviceFound);
    }
    {
        wrapper.Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_NON);
        EXPECT_TRUE(g_isDeviceFound);
    }
    {
        wrapper.Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_NON_WITH_BR_ADDR);
        EXPECT_TRUE(g_isDeviceFound);
    }
    {
        wrapper.Call(CMD::BLE_STOP_SCAN, 1).Build();
        ret = interface->mediumInterface->Unsubscribe(&g_subscribeOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    DiscSoftBusBleDeinit();
}

/*
 * @tc.name: PublishActive001
 * @tc.desc: should start adv NON without br addr when PUBLISH_ACTIVE_SERVICE with br & ble enable
 *           should do nothing when recv CON / NON packet
 *           should stop adv when UNPUBLISH_SERVICE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, PublishActive001, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_ON);
    ExpectWrapper wrapper(mock);

    DiscoveryBleDispatcherInterface *interface = DiscSoftBusBleInit(&g_discInnerCallback);
    AssertInterfaceIsNotNull(interface);
    SoftBusBtInit();
    int32_t ret = SOFTBUS_OK;
    {
        wrapper.Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 0).Build();
        ret = interface->mediumInterface->Publish(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
        mock.CallbackAdvEnable();
    }
    {
        wrapper.Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_CON);
        EXPECT_FALSE(g_isDeviceFound);
        mock.CallbackScanResult(PACKET_NON);
        EXPECT_FALSE(g_isDeviceFound);
        mock.CallbackScanResult(PACKET_NON_WITH_BR_ADDR);
        EXPECT_FALSE(g_isDeviceFound);
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Build();
        ret = interface->mediumInterface->Unpublish(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    DiscSoftBusBleDeinit();
}

/*
 * @tc.name: PublishPassive001
 * @tc.desc: should start scan when PUBLISH_PASSIVE_SERVICE with br & ble enable
 *           should do nothing when recv NON packet
 *           should start adv NON with br addr when recv CON packet with br enable
 *           should stop adv and stop scan when UNPUBLISH_SERVICE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, PublishPassive001, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_ON);
    ExpectWrapper wrapper(mock);

    DiscoveryBleDispatcherInterface *interface = DiscSoftBusBleInit(&g_discInnerCallback);
    AssertInterfaceIsNotNull(interface);
    SoftBusBtInit();
    int32_t ret = SOFTBUS_OK;
    {
        wrapper.Call(CMD::BLE_START_SCAN_EX, 1).Build();
        ret = interface->mediumInterface->StartScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    {
        wrapper.Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_NON);
        EXPECT_FALSE(g_isDeviceFound);
    }
    {
        wrapper.Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 1).Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_CON);
        EXPECT_FALSE(g_isDeviceFound);
        mock.CallbackAdvEnable(); // REPLY_PASSIVE_NON_BROADCAST
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Call(CMD::BLE_STOP_SCAN, 1).Build();
        ret = interface->mediumInterface->StopScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    DiscSoftBusBleDeinit();
}

/*
 * @tc.name: PublishPassive002
 * @tc.desc: should start scan when PUBLISH_PASSIVE_SERVICE with br disable and ble enable
 *           should do nothing when recv NON packet
 *           should start adv NON without br addr when recv CON packet with br disable
 *           should stop adv and stop scan when UNPUBLISH_SERVICE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, PublishPassive002, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_RESTRICT);
    ExpectWrapper wrapper(mock);

    DiscoveryBleDispatcherInterface *interface = DiscSoftBusBleInit(&g_discInnerCallback);
    AssertInterfaceIsNotNull(interface);
    SoftBusBtInit();
    int32_t ret = SOFTBUS_OK;
    {
        wrapper.Call(CMD::BLE_START_SCAN_EX, 1).Build();
        ret = interface->mediumInterface->StartScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    {
        wrapper.Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_NON);
        EXPECT_FALSE(g_isDeviceFound);
    }
    {
        wrapper.Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 0).Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_CON);
        EXPECT_FALSE(g_isDeviceFound);
        mock.CallbackAdvEnable(); // REPLY_PASSIVE_NON_BROADCAST
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Call(CMD::BLE_STOP_SCAN, 1).Build();
        ret = interface->mediumInterface->StopScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    DiscSoftBusBleDeinit();
}

/*
 * @tc.name: PublishPassive003
 * @tc.desc: should update adv without br addr when REPLY_PASSIVE_NON_BROADCAST and br on -> off
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, PublishPassive003, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_ON);
    ExpectWrapper wrapper(mock);

    DiscoveryBleDispatcherInterface *interface = DiscSoftBusBleInit(&g_discInnerCallback);
    AssertInterfaceIsNotNull(interface);
    SoftBusBtInit();
    int32_t ret = SOFTBUS_OK;
    {
        wrapper.Call(CMD::BLE_START_SCAN_EX, 1).Build();
        ret = interface->mediumInterface->StartScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    {
        wrapper.Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_NON);
        EXPECT_FALSE(g_isDeviceFound);
        mock.CallbackScanResult(PACKET_NON_WITH_BR_ADDR);
        EXPECT_FALSE(g_isDeviceFound);
    }
    {
        wrapper.Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 1).Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_CON);
        EXPECT_FALSE(g_isDeviceFound);
        mock.CallbackAdvEnable(); // REPLY_PASSIVE_NON_BROADCAST
    }
    {
        wrapper.Call(CMD::BLE_SET_ADV_DATA, 1).Call(CMD::GET_LOCAL_ADDR, 0).Build();
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_RESTRICT);
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Call(CMD::BLE_STOP_SCAN, 1).Build();
        ret = interface->mediumInterface->StopScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    DiscSoftBusBleDeinit();
}

/*
 * @tc.name: PublishPassive004
 * @tc.desc: should update adv with br addr when REPLY_PASSIVE_NON_BROADCAST and br off -> on
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, PublishPassive004, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_RESTRICT);
    ExpectWrapper wrapper(mock);

    DiscoveryBleDispatcherInterface *interface = DiscSoftBusBleInit(&g_discInnerCallback);
    AssertInterfaceIsNotNull(interface);
    SoftBusBtInit();
    int32_t ret = SOFTBUS_OK;
    {
        wrapper.Call(CMD::BLE_START_SCAN_EX, 1).Build();
        ret = interface->mediumInterface->StartScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    {
        wrapper.Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_NON);
        EXPECT_FALSE(g_isDeviceFound);
        mock.CallbackScanResult(PACKET_NON_WITH_BR_ADDR);
        EXPECT_FALSE(g_isDeviceFound);
    }
    {
        wrapper.Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 0).Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_CON);
        EXPECT_FALSE(g_isDeviceFound);
        mock.CallbackAdvEnable(); // REPLY_PASSIVE_NON_BROADCAST
    }
    {
        wrapper.Call(CMD::BLE_SET_ADV_DATA, 1).Call(CMD::GET_LOCAL_ADDR, 1).Build();
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_ON);
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Call(CMD::BLE_STOP_SCAN, 1).Build();
        ret = interface->mediumInterface->StopScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    DiscSoftBusBleDeinit();
}

/*
 * @tc.name: PublishPassive005
 * @tc.desc: bluetooth state convert: ON -> RESTRICT, RESTRICT -> ON, ON -> OFF
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, PublishPassive005, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_ON);
    ExpectWrapper wrapper(mock);

    DiscoveryBleDispatcherInterface *interface = DiscSoftBusBleInit(&g_discInnerCallback);
    AssertInterfaceIsNotNull(interface);
    SoftBusBtInit();
    int32_t ret = SOFTBUS_OK;
    {
        wrapper.Call(CMD::BLE_START_SCAN_EX, 1).Build();
        ret = interface->mediumInterface->StartScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    {
        wrapper.Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 1).Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_CON);
        EXPECT_FALSE(g_isDeviceFound);
        mock.CallbackAdvEnable();
    }
    {
        wrapper.Call(CMD::BLE_SET_ADV_DATA, 1).Call(CMD::GET_LOCAL_ADDR, 0).Build();
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_RESTRICT);
    }
    {
        wrapper.Call(CMD::BLE_SET_ADV_DATA, 1).Call(CMD::GET_LOCAL_ADDR, 1).Build();
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_ON);
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Call(CMD::BLE_STOP_SCAN, 1).Build();
        EXPECT_CALL(mock, BleSetAdvData).Times(AtMost(1));
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_OFF);
    }
    {
        wrapper.Build();
        ret = interface->mediumInterface->StopScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    DiscSoftBusBleDeinit();
}

/*
 * @tc.name: PublishPassive006
 * @tc.desc: bluetooth state convert: ON -> RESTRICT, RESTRICT -> OFF, OFF -> ON, ON -> OFF
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, PublishPassive006, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_ON);
    ExpectWrapper wrapper(mock);

    DiscoveryBleDispatcherInterface *interface = DiscSoftBusBleInit(&g_discInnerCallback);
    AssertInterfaceIsNotNull(interface);
    SoftBusBtInit();
    int32_t ret = SOFTBUS_OK;
    {
        wrapper.Call(CMD::BLE_START_SCAN_EX, 1).Build();
        ret = interface->mediumInterface->StartScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    {
        wrapper.Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 1).Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_CON);
        EXPECT_FALSE(g_isDeviceFound);
        mock.CallbackAdvEnable(); // REPLY_PASSIVE_NON_BROADCAST
    }
    {
        wrapper.Call(CMD::BLE_SET_ADV_DATA, 1).Call(CMD::GET_LOCAL_ADDR, 0).Build();
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_RESTRICT);
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Call(CMD::BLE_STOP_SCAN, 1).Build();
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_OFF);
    }
    {
        wrapper.Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 1).Call(CMD::BLE_START_SCAN_EX, 1).Build();
        EXPECT_CALL(mock, BleSetAdvData).Times(AtMost(1));
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_ON);
        mock.CallbackAdvEnable();
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Call(CMD::BLE_STOP_SCAN, 1).Build();
        EXPECT_CALL(mock, BleSetAdvData).Times(AtMost(1));
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_OFF);
    }
    {
        wrapper.Build();
        ret = interface->mediumInterface->StopScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    DiscSoftBusBleDeinit();
}

/*
 * @tc.name: PublishPassive007
 * @tc.desc: bluetooth state convert: ON -> OFF, OFF -> ON, ON -> RESTRICT, RESTRICT -> OFF
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, PublishPassive007, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_ON);
    ExpectWrapper wrapper(mock);

    DiscoveryBleDispatcherInterface *interface = DiscSoftBusBleInit(&g_discInnerCallback);
    AssertInterfaceIsNotNull(interface);
    SoftBusBtInit();
    int32_t ret = SOFTBUS_OK;
    {
        wrapper.Call(CMD::BLE_START_SCAN_EX, 1).Build();
        ret = interface->mediumInterface->StartScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    {
        wrapper.Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 1).Build();
        EXPECT_CALL(mock, BleSetAdvData).Times(AtMost(1));
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_CON);
        EXPECT_FALSE(g_isDeviceFound);
        mock.CallbackAdvEnable(); // REPLY_PASSIVE_NON_BROADCAST
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Call(CMD::BLE_STOP_SCAN, 1).Build();
        EXPECT_CALL(mock, BleSetAdvData).Times(AtMost(1));
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_OFF);
    }
    {
        wrapper.Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 1).Call(CMD::BLE_START_SCAN_EX, 1).Build();
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_ON);
        mock.CallbackAdvEnable();
    }
    {
        wrapper.Call(CMD::BLE_SET_ADV_DATA, 1).Call(CMD::GET_LOCAL_ADDR, 0).Build();
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_RESTRICT);
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Call(CMD::BLE_STOP_SCAN, 1).Build();
        EXPECT_CALL(mock, BleSetAdvData).Times(AtMost(1));
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_OFF);
    }
    {
        wrapper.Build();
        ret = interface->mediumInterface->StopScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    DiscSoftBusBleDeinit();
}

/*
 * @tc.name: PublishPassive008
 * @tc.desc: bluetooth state convert: RESTRICT -> OFF, OFF -> ON, ON -> RESTRICT, RESTRICT -> ON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscBtStateTest, PublishPassive008, TestSize.Level1)
{
    NiceMock<BluetoothMock> mock(BluetoothMock::BtState::BT_STATE_RESTRICT);
    ExpectWrapper wrapper(mock);

    DiscoveryBleDispatcherInterface *interface = DiscSoftBusBleInit(&g_discInnerCallback);
    AssertInterfaceIsNotNull(interface);
    SoftBusBtInit();
    int32_t ret = SOFTBUS_OK;
    {
        wrapper.Call(CMD::BLE_START_SCAN_EX, 1).Build();
        ret = interface->mediumInterface->StartScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    {
        wrapper.Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 0).Build();
        g_isDeviceFound = false;
        mock.CallbackScanResult(PACKET_CON);
        EXPECT_FALSE(g_isDeviceFound);
        mock.CallbackAdvEnable(); // REPLY_PASSIVE_NON_BROADCAST
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Call(CMD::BLE_STOP_SCAN, 1).Build();
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_OFF);
    }
    {
        wrapper.Call(CMD::BLE_START_ADV_EX, 1).Call(CMD::GET_LOCAL_ADDR, 1).Call(CMD::BLE_START_SCAN_EX, 1).Build();
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_ON);
        mock.CallbackAdvEnable();
    }
    {
        wrapper.Call(CMD::BLE_SET_ADV_DATA, 1).Call(CMD::GET_LOCAL_ADDR, 0).Build();
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_RESTRICT);
    }
    {
        wrapper.Call(CMD::BLE_SET_ADV_DATA, 1).Call(CMD::GET_LOCAL_ADDR, 1).Build();
        mock.ConvertBtState(BluetoothMock::BtState::BT_STATE_ON);
    }
    {
        wrapper.Call(CMD::BLE_STOP_ADV, 1).Call(CMD::BLE_STOP_SCAN, 1).Build();
        ret = interface->mediumInterface->StopScan(&g_publishOption);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SleepMs(SLEEP_TIME);
    }
    DiscSoftBusBleDeinit();
}
} // namespace OHOS
