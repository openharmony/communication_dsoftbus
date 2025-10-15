/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "bus_center_event.h"
#include "lnn_network_manager.h"
#include "lnn_physical_subnet_manager.h"
#include "lnn_trans_mock.h"
#include "lnn_usb_network_impl.c"
#include "lnn_usb_network_impl_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

LnnProtocolManager self;
LnnNetIfMgr netifMgr;

class LNNUsbNetworkImplMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNUsbNetworkImplMockTest::SetUpTestCase()
{
    LooperInit();
}

void LNNUsbNetworkImplMockTest::TearDownTestCase()
{
    LooperDeinit();
}

void LNNUsbNetworkImplMockTest::SetUp() { }

void LNNUsbNetworkImplMockTest::TearDown() { }

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_001
 * @tc.desc: LnnEnableUsbProtocol Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_001, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;

    EXPECT_CALL(usbMock, LnnRegistPhysicalSubnet)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));

    memset_s(&self, sizeof(LnnProtocolManager), 0, sizeof(LnnProtocolManager));
    memset_s(&netifMgr, sizeof(LnnNetIfMgr), 0, sizeof(LnnNetIfMgr));
    int32_t ret = strcpy_s(netifMgr.ifName, sizeof("name"), "name");
    ASSERT_EQ(ret, EOK);

    int32_t res = LnnEnableUsbProtocol(nullptr, nullptr);
    EXPECT_NE(res, SOFTBUS_OK);
    res = LnnEnableUsbProtocol(&self, &netifMgr);
    EXPECT_NE(res, SOFTBUS_OK);
    res = LnnEnableUsbProtocol(&self, &netifMgr);
    EXPECT_EQ(res, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_002
 * @tc.desc: LnnInitUsbProtocol Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_002, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;

    EXPECT_CALL(usbMock, LnnRegisterEventHandler).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(usbMock, LnnSetLocalStrInfoByIfnameIdx)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));

    int32_t res = LnnInitUsbProtocol(&self);
    EXPECT_NE(res, SOFTBUS_OK);

    EXPECT_CALL(usbMock, LnnRegisterEventHandler)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    res = LnnInitUsbProtocol(&self);
    EXPECT_NE(res, SOFTBUS_OK);
    res = LnnInitUsbProtocol(&self);
    EXPECT_NE(res, SOFTBUS_OK);
    res = LnnInitUsbProtocol(&self);
    EXPECT_EQ(res, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_003
 * @tc.desc: LnnGetUsbListenerModule Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_003, TestSize.Level1)
{
    ListenerModule ret = LnnGetUsbListenerModule(LNN_LISTENER_MODE_PROXY);
    EXPECT_EQ(ret, DIRECT_CHANNEL_SERVER_USB);
    ret = LnnGetUsbListenerModule(LNN_LISTENER_MODE_DIRECT);
    EXPECT_EQ(ret, DIRECT_CHANNEL_SERVER_USB);
    ret = LnnGetUsbListenerModule(LNN_LISTENER_MODE_AUTH);
    EXPECT_EQ(ret, UNUSE_BUTT);

    LnnDeinitUsbNetwork(&self);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_004
 * @tc.desc: NotifyUsbAddressChanged Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_004, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;
    EXPECT_CALL(usbMock, LnnNotifyPhysicalSubnetStatusChanged).WillRepeatedly(Return());

    VisitNextChoice visit = NotifyUsbAddressChanged(nullptr, nullptr);
    EXPECT_EQ(visit, CHOICE_VISIT_NEXT);
    netifMgr.type = LNN_NETIF_TYPE_WLAN;
    visit = NotifyUsbAddressChanged(&netifMgr, nullptr);
    EXPECT_EQ(visit, CHOICE_VISIT_NEXT);
    netifMgr.type = LNN_NETIF_TYPE_USB;
    visit = NotifyUsbAddressChanged(&netifMgr, nullptr);
    EXPECT_EQ(visit, CHOICE_VISIT_NEXT);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_005
 * @tc.desc: OnIpNetifStatusChanged Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_005, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;

    EXPECT_CALL(usbMock, GetNetworkIpv6ByIfName).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_IP_ADDR_FAILED));
    EXPECT_CALL(usbMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(usbMock, LnnGetLocalStrInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_OK));

    LnnProtocolManager lnnProtocolManager = {
        .id = LNN_PROTOCOL_IP,
    };
    LnnPhysicalSubnet subnet = {
        .protocol = &lnnProtocolManager,
        .status = LNN_SUBNET_RUNNING,
    };
    OnIpNetifStatusChanged(&subnet, nullptr);
    EXPECT_EQ(subnet.status, LNN_SUBNET_SHUTDOWN);

    subnet.status = LNN_SUBNET_IDLE;
    OnIpNetifStatusChanged(&subnet, nullptr);
    EXPECT_EQ(subnet.status, LNN_SUBNET_IDLE);

    IpSubnetManagerEvent *eventPtr = static_cast<IpSubnetManagerEvent *>(SoftBusCalloc(sizeof(IpSubnetManagerEvent)));
    ASSERT_TRUE(eventPtr != nullptr);
    *eventPtr = USB_SUBNET_MANAGER_EVENT_IF_READY;
    subnet.status = LNN_SUBNET_IDLE;
    OnIpNetifStatusChanged(&subnet, (void *)eventPtr);
    EXPECT_EQ(subnet.status, LNN_SUBNET_IDLE);

    eventPtr = static_cast<IpSubnetManagerEvent *>(SoftBusCalloc(sizeof(IpSubnetManagerEvent)));
    ASSERT_TRUE(eventPtr != nullptr);
    *eventPtr = USB_SUBNET_MANAGER_EVENT_IF_CHANGED;
    subnet.status = LNN_SUBNET_IDLE;
    OnIpNetifStatusChanged(&subnet, (void *)eventPtr);
    EXPECT_EQ(subnet.status, LNN_SUBNET_RESETTING);

    eventPtr = static_cast<IpSubnetManagerEvent *>(SoftBusCalloc(sizeof(IpSubnetManagerEvent)));
    ASSERT_TRUE(eventPtr != nullptr);
    *eventPtr = (IpSubnetManagerEvent)(USB_SUBNET_MANAGER_EVENT_IF_READY - 1);
    subnet.status = LNN_SUBNET_IDLE;
    OnIpNetifStatusChanged(&subnet, (void *)eventPtr);
    EXPECT_EQ(subnet.status, LNN_SUBNET_IDLE);

    eventPtr = static_cast<IpSubnetManagerEvent *>(SoftBusCalloc(sizeof(IpSubnetManagerEvent)));
    ASSERT_TRUE(eventPtr != nullptr);
    *eventPtr = (IpSubnetManagerEvent)(USB_SUBNET_MANAGER_EVENT_MAX + 1);
    subnet.status = LNN_SUBNET_IDLE;
    OnIpNetifStatusChanged(&subnet, (void *)eventPtr);
    EXPECT_EQ(subnet.status, LNN_SUBNET_IDLE);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_006
 * @tc.desc: OnSoftbusIpNetworkDisconnected Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_006, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;

    EXPECT_CALL(usbMock, GetNetworkIpv6ByIfName).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_IP_ADDR_FAILED));

    LnnProtocolManager lnnProtocolManager = {
        .id = LNN_PROTOCOL_IP,
    };
    LnnPhysicalSubnet subnet = {
        .protocol = &lnnProtocolManager,
        .status = LNN_SUBNET_RUNNING,
    };

    OnSoftbusIpNetworkDisconnected(nullptr);
    subnet.status = LNN_SUBNET_RESETTING;
    OnSoftbusIpNetworkDisconnected(&subnet);
    EXPECT_EQ(subnet.status, LNN_SUBNET_IDLE);

    subnet.status = LNN_SUBNET_IDLE;
    OnSoftbusIpNetworkDisconnected(&subnet);
    EXPECT_EQ(subnet.status, LNN_SUBNET_IDLE);

    subnet.status = LNN_SUBNET_RUNNING;
    OnSoftbusIpNetworkDisconnected(&subnet);
    EXPECT_EQ(subnet.status, LNN_SUBNET_RUNNING);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_007
 * @tc.desc: DestroyUsbSubnetManager Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_007, TestSize.Level1)
{
    DestroyUsbSubnetManager(nullptr);

    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;
    EXPECT_CALL(usbMock, LnnSetLocalNumInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_OK));
    LnnPhysicalSubnet *subnetPtr = static_cast<LnnPhysicalSubnet *>(SoftBusCalloc(sizeof(LnnPhysicalSubnet)));
    ASSERT_TRUE(subnetPtr != nullptr);
    subnetPtr->status = LNN_SUBNET_RUNNING;
    DestroyUsbSubnetManager(subnetPtr);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_008
 * @tc.desc: GetAvailableIpAddr Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_008, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;
    EXPECT_CALL(usbMock, GetNetworkIpv6ByIfName)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(LnnUsbNetworkImplInterfaceMock::ActionOfGetNetworkIpv6ByIfName);
    char address[IP_LEN] = { 0 };
    int32_t ret = GetAvailableIpAddr("usb", address, sizeof(address));
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = GetAvailableIpAddr("ncm0", address, sizeof(address));
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = GetAvailableIpAddr("ncm0", address, sizeof(address));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_009
 * @tc.desc: GetIpEventInRunning And GetIpEventInOther Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_009, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;

    EXPECT_CALL(usbMock, GetNetworkIpv6ByIfName)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(LnnUsbNetworkImplInterfaceMock::ActionOfGetNetworkIpv6ByIfName);
    EXPECT_CALL(usbMock, LnnGetLocalStrInfoByIfnameIdx)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(LnnUsbNetworkImplInterfaceMock::ActionOfLnnGetLocalStrInfoByIfnameIdx);
    LnnPhysicalSubnet subnet = {
        .ifName = "noDeviceName",
        .status = LNN_SUBNET_RUNNING,
    };
    IpSubnetManagerEvent res = GetIpEventInRunning(&subnet);
    EXPECT_EQ(res, USB_SUBNET_MANAGER_EVENT_IF_DOWN);

    res = GetIpEventInRunning(&subnet);
    EXPECT_EQ(res, USB_SUBNET_MANAGER_EVENT_IF_READY);

    res = GetIpEventInRunning(&subnet);
    EXPECT_EQ(res, USB_SUBNET_MANAGER_EVENT_IF_READY);

    int32_t ret = strcpy_s(subnet.ifName, sizeof("deviceName"), "deviceName");
    ASSERT_EQ(ret, EOK);

    res = GetIpEventInRunning(&subnet);
    EXPECT_EQ(res, USB_SUBNET_MANAGER_EVENT_MAX);

    EXPECT_CALL(usbMock, GetNetworkIpv6ByIfName)
        .WillOnce(LnnUsbNetworkImplInterfaceMock::ActionOfGetNetworkIpv6ByIfName2);
    res = GetIpEventInRunning(&subnet);
    EXPECT_EQ(res, USB_SUBNET_MANAGER_EVENT_IF_CHANGED);

    EXPECT_CALL(usbMock, GetNetworkIpv6ByIfName)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(LnnUsbNetworkImplInterfaceMock::ActionOfGetNetworkIpv6ByIfName);
    subnet.status = LNN_SUBNET_SHUTDOWN;
    res = GetIpEventInOther(&subnet);
    EXPECT_EQ(res, USB_SUBNET_MANAGER_EVENT_IF_DOWN);

    res = GetIpEventInOther(&subnet);
    EXPECT_EQ(res, USB_SUBNET_MANAGER_EVENT_IF_READY);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_010
 * @tc.desc: add ip and port to ledger
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_010, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;
    EXPECT_CALL(usbMock, LnnGetLocalStrInfoByIfnameIdx)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(LnnUsbNetworkImplInterfaceMock::ActionOfLnnGetLocalStrInfoByIfnameIdx);
    EXPECT_CALL(usbMock, LnnSetLocalStrInfoByIfnameIdx)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = RequestMainPort("lo", "::1");
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = RequestMainPort("ncm0", "::1");
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = RequestMainPort("ncm0", "::2");
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = RequestMainPort("ncm0", "::2");
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = RequestMainPort("deviceName", "::2");
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = RequestMainPort("deviceName", "::2");
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_011
 * @tc.desc: OpenAuthPort Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_011, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;
    EXPECT_CALL(usbMock, LnnGetLocalNumInfoByIfnameIdx)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, LnnGetLocalStrInfoByIfnameIdx)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, AuthStartListening).WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, LnnSetLocalNumInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = OpenAuthPort();
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = OpenAuthPort();
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = OpenAuthPort();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_012
 * @tc.desc: OpenSessionPort Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_012, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;
    EXPECT_CALL(usbMock, LnnGetLocalNumInfoByIfnameIdx)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, LnnGetLocalStrInfoByIfnameIdx)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, TransTdcStartSessionListener)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, LnnSetLocalNumInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = OpenSessionPort();
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = OpenSessionPort();
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = OpenSessionPort();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = OpenSessionPort();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_013
 * @tc.desc: OpenIpLink Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_013, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;
    EXPECT_CALL(usbMock, LnnGetLocalNumInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(usbMock, LnnGetLocalStrInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, LnnSetLocalNumInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, AuthStartListening).WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, TransTdcStartSessionListener)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = OpenIpLink();
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = OpenIpLink();
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = OpenIpLink();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_014
 * @tc.desc: EnableIpSubnet Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_014, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;
    LnnPhysicalSubnet subnet = {
        .ifName = "deviceName",
        .status = LNN_SUBNET_RUNNING,
    };
    EXPECT_CALL(usbMock, GetNetworkIpv6ByIfName)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(LnnUsbNetworkImplInterfaceMock::ActionOfGetNetworkIpv6ByIfName);
    int32_t ret = EnableIpSubnet(&subnet);
    EXPECT_NE(ret, SOFTBUS_OK);

    int32_t cpyRet = strcpy_s(subnet.ifName, sizeof("lo"), "lo");
    ASSERT_EQ(cpyRet, EOK);
    ret = EnableIpSubnet(&subnet);
    EXPECT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(usbMock, LnnGetLocalStrInfoByIfnameIdx)
        .WillRepeatedly(LnnUsbNetworkImplInterfaceMock::ActionOfLnnGetLocalStrInfoByIfnameIdx);
    EXPECT_CALL(usbMock, LnnGetLocalNumInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(usbMock, LnnSetLocalNumInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, AuthStartListening).WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, TransTdcStartSessionListener).WillRepeatedly(Return(SOFTBUS_OK));

    cpyRet = strcpy_s(subnet.ifName, sizeof("deviceName"), "deviceName");
    ASSERT_EQ(cpyRet, EOK);
    ret = EnableIpSubnet(&subnet);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = EnableIpSubnet(&subnet);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(usbMock, LnnGetLocalNumU32Info)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, LnnSetNetCapability).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, LnnClearNetCapability).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, LnnSetLocalNumInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));

    ret = EnableIpSubnet(&subnet);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = EnableIpSubnet(&subnet);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_015
 * @tc.desc: release ip and port to ledger
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_015, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;
    EXPECT_CALL(usbMock, LnnGetLocalStrInfoByIfnameIdx)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(LnnUsbNetworkImplInterfaceMock::ActionOfLnnGetLocalStrInfoByIfnameIdx);
    EXPECT_CALL(usbMock, LnnSetLocalStrInfoByIfnameIdx)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = ReleaseMainPort("deviceName");
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ReleaseMainPort("deviceName1");
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ReleaseMainPort("deviceName");
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(usbMock, LnnGetAddrTypeByIfName)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(usbMock, LnnRequestLeaveByAddrType)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LeaveOldIpNetwork(nullptr);
    LeaveOldIpNetwork(nullptr);
    LeaveOldIpNetwork(nullptr);

    EXPECT_CALL(usbMock, LnnSetLocalNumInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_OK));
    CloseAuthPort();
    CloseSessionPort();

    memset_s(&self, sizeof(LnnProtocolManager), 0, sizeof(LnnProtocolManager));
    LnnDeinitUsbNetwork(&self);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_016
 * @tc.desc: IsValidUsbIfname Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_016, TestSize.Level1)
{
    EXPECT_FALSE(IsValidUsbIfname(nullptr));
    EXPECT_FALSE(IsValidUsbIfname("usb"));
    EXPECT_TRUE(IsValidUsbIfname("ncm0"));
    EXPECT_TRUE(IsValidUsbIfname("wwan0"));
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_017
 * @tc.desc: IpAddrChangeEventHandler Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_017, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;
    LnnMonitorAddressChangedEvent event = { .basic.event = LNN_EVENT_WIFI_STATE_CHANGED, .ifName = { 0 } };
    IpAddrChangeEventHandler(nullptr);
    IpAddrChangeEventHandler((const LnnEventBasicInfo *)&event);
    EXPECT_NE(event.basic.event, LNN_EVENT_IP_ADDR_CHANGED);

    event.basic.event = LNN_EVENT_IP_ADDR_CHANGED;
    IpAddrChangeEventHandler((const LnnEventBasicInfo *)&event);
    EXPECT_EQ(event.basic.event, LNN_EVENT_IP_ADDR_CHANGED);

    EXPECT_CALL(usbMock, LnnNotifyPhysicalSubnetStatusChanged).WillRepeatedly(Return());
    int32_t ret = strcpy_s(event.ifName, sizeof("ncm0"), "ncm0");
    ASSERT_EQ(ret, EOK);
    IpAddrChangeEventHandler((const LnnEventBasicInfo *)&event);
    EXPECT_EQ(event.basic.event, LNN_EVENT_IP_ADDR_CHANGED);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_018
 * @tc.desc: UsbNcmChangeHandler Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_018, TestSize.Level1)
{
    LnnMonitorNetlinkStateInfo event = {
        .basic.event = LNN_EVENT_DEVICE_INFO_CHANGED, .status = SOFTBUS_NETMANAGER_IFNAME_REMOVED, .ifName = { 0 }
    };
    UsbNcmChangeHandler(nullptr);
    UsbNcmChangeHandler((const LnnEventBasicInfo *)&event);
    EXPECT_NE(event.basic.event, LNN_EVENT_NET_LINK_STATE_CHANGE);

    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;
    EXPECT_CALL(usbMock, LnnNotifyPhysicalSubnetStatusChanged).WillRepeatedly(Return());
    event.basic.event = LNN_EVENT_NET_LINK_STATE_CHANGE;
    UsbNcmChangeHandler((const LnnEventBasicInfo *)&event);
    EXPECT_EQ(event.basic.event, LNN_EVENT_NET_LINK_STATE_CHANGE);

    int32_t ret = strcpy_s(event.ifName, sizeof("usb"), "usb");
    ASSERT_EQ(ret, EOK);
    UsbNcmChangeHandler((const LnnEventBasicInfo *)&event);
    EXPECT_EQ(event.basic.event, LNN_EVENT_NET_LINK_STATE_CHANGE);

    ret = strcpy_s(event.ifName, sizeof("ncm0"), "ncm0");
    ASSERT_EQ(ret, EOK);
    UsbNcmChangeHandler((const LnnEventBasicInfo *)&event);
    EXPECT_EQ(event.status, SOFTBUS_NETMANAGER_IFNAME_REMOVED);

    event.status = SOFTBUS_NETMANAGER_IFNAME_ADDED;
    UsbNcmChangeHandler((const LnnEventBasicInfo *)&event);
    EXPECT_NE(event.status, SOFTBUS_NETMANAGER_IFNAME_REMOVED);
}

/*
 * @tc.name: LNN_USB_NETWORK_IMPL_TEST_019
 * @tc.desc: RegistUsbProtocolManager Test
 * @tc.type: FUNC
 * @tc.require: NONE
 * @tc.level: Level1
 */
HWTEST_F(LNNUsbNetworkImplMockTest, LNN_USB_NETWORK_IMPL_TEST_019, TestSize.Level1)
{
    NiceMock<LnnUsbNetworkImplInterfaceMock> usbMock;
    EXPECT_CALL(usbMock, LnnRegistProtocol).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = RegistUsbProtocolManager();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

} // namespace OHOS