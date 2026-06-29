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

#include <csignal>
#include <gtest/gtest.h>
#include "data/inner_link.h"
#include "data/link_manager.h"

using namespace testing::ext;

namespace OHOS::SoftBus {
class InnerLinkTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: SetAndGetEnum
 * @tc.desc: check set and get methods of enum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, SetAndGetEnum, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.GetLinkType(), InnerLink::LinkType::INVALID_TYPE);
    info.SetLinkType(InnerLink::LinkType::HML);
    EXPECT_EQ(info.GetLinkType(), InnerLink::LinkType::HML);

    EXPECT_EQ(info.GetState(), InnerLink::LinkState::INVALID_STATE);
    info.SetState(InnerLink::LinkState::CONNECTING);
    EXPECT_EQ(info.GetState(), InnerLink::LinkState::CONNECTING);

    EXPECT_EQ(info.GetListenerModule(), static_cast<ListenerModule>(UNUSE_BUTT));
    info.SetListenerModule(ListenerModule::LISTENER_MODULE_DYNAMIC_START);
    EXPECT_EQ(info.GetListenerModule(), ListenerModule::LISTENER_MODULE_DYNAMIC_START);
}

/*
 * @tc.name: SetAndGetString
 * @tc.desc: check set and get methods if string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, SetAndGetString, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.GetLocalInterface(), "");
    info.SetLocalInterface(IF_NAME_P2P);
    EXPECT_EQ(info.GetLocalInterface(), IF_NAME_P2P);

    EXPECT_EQ(info.GetLocalBaseMac(), "");
    info.SetLocalBaseMac("00:11:22:33:44:55");
    EXPECT_EQ(info.GetLocalBaseMac(), "00:11:22:33:44:55");

    EXPECT_EQ(info.GetLocalDynamicMac(), "");
    info.SetLocalDynamicMac("00:01:02:03:04:05");
    EXPECT_EQ(info.GetLocalDynamicMac(), "00:01:02:03:04:05");

    EXPECT_EQ(info.GetLocalIpv4(), "");
    info.SetLocalIpv4("127.0.0.1");
    EXPECT_EQ(info.GetLocalIpv4(), "127.0.0.1");

    EXPECT_EQ(info.GetRemoteInterface(), "");
    info.SetRemoteInterface("p2p0-1");
    EXPECT_EQ(info.GetRemoteInterface(), "p2p0-1");

    EXPECT_EQ(info.GetRemoteBaseMac(), "");
    info.SetRemoteBaseMac("AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(info.GetRemoteBaseMac(), "AA:BB:CC:DD:EE:FF");

    EXPECT_EQ(info.GetRemoteDynamicMac(), "");
    info.SetRemoteDynamicMac("A0:A1:A2:A3:A4:A5");
    EXPECT_EQ(info.GetRemoteDynamicMac(), "A0:A1:A2:A3:A4:A5");

    EXPECT_EQ(info.GetRemoteIpv4(), "");
    info.SetRemoteIpv4("10.0.0.1");
    EXPECT_EQ(info.GetRemoteIpv4(), "10.0.0.1");

    EXPECT_EQ(info.GetRemoteDeviceId(), "");
    info.SetRemoteDeviceId("0123456789ABCDEF");
    EXPECT_EQ(info.GetRemoteDeviceId(), "0123456789ABCDEF");
}

/*
 * @tc.name: SetAndGetBool
 * @tc.desc: check set and get methods of boolean
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, SetAndGetBool, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.IsBeingUsedByLocal(), false);
    WifiDirectLink link {};
    info.GenerateLink(6, 8, link, false);
    EXPECT_EQ(info.IsBeingUsedByLocal(), true);

    EXPECT_EQ(info.IsBeingUsedByRemote(), false);
    info.SetBeingUsedByRemote(true);
    EXPECT_EQ(info.IsBeingUsedByRemote(), true);

    EXPECT_EQ(info.HasPtk(), false);
    info.SetPtk(true);
    EXPECT_EQ(info.HasPtk(), true);

    EXPECT_EQ(info.GetNewPtkFrame(), false);
    info.SetNewPtkFrame(true);
    EXPECT_EQ(info.GetNewPtkFrame(), true);

    EXPECT_EQ(info.GetLegacyReused(), false);
    info.SetLegacyReused(true);
    EXPECT_EQ(info.GetLegacyReused(), true);
}

/*
 * @tc.name: SetAndGetInt
 * @tc.desc: check set and get methods of int
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, SetAndGetInt, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.GetFrequency(), -1);
    info.SetFrequency(149);
    EXPECT_EQ(info.GetFrequency(), 149);

    EXPECT_EQ(info.GetLocalPort(), -1);
    info.SetLocalPort(443);
    EXPECT_EQ(info.GetLocalPort(), 443);

    EXPECT_EQ(info.GetRemotePort(), -1);
    info.SetRemotePort(8888);
    EXPECT_EQ(info.GetRemotePort(), 8888);

    EXPECT_EQ(info.GetReference(), 0);
    WifiDirectLink link {};
    info.GenerateLink(1, 2, link, false);
    EXPECT_EQ(info.GetReference(), 1);
    info.RemoveId(link.linkId);
    EXPECT_EQ(info.GetReference(), 0);
}

/*
 * @tc.name: SetAndGetGrocery
 * @tc.desc: check set and get methods of int
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, SetAndGetGrocery, TestSize.Level1)
{
    InnerLink info("");

    WifiDirectLink link {};
    info.GenerateLink(888, 666, link, false);
    EXPECT_EQ(info.IsContainId(link.linkId), true) << "IsContainId done";
    info.RemoveId(link.linkId);
    EXPECT_EQ(info.IsContainId(link.linkId), false) << "IsContainId done";

    EXPECT_EQ(info.IsProtected(), false);
    info.SetState(InnerLink::LinkState::CONNECTING);
    EXPECT_EQ(info.IsProtected(), false);
    info.SetState(InnerLink::LinkState::CONNECTED);
    EXPECT_EQ(info.IsProtected(), true);
}

/*
 * @tc.name: ToString
 * @tc.desc: test the to string method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, TypeToString, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.ToString(InnerLink::LinkType::INVALID_TYPE), "INVALID_TYPE");
    EXPECT_EQ(info.ToString(InnerLink::LinkType::HML), "HML");
    EXPECT_EQ(info.ToString(InnerLink::LinkType::P2P), "P2P");
    EXPECT_EQ(info.ToString(InnerLink::LinkState::INVALID_STATE), "INVALID_STATE");
    EXPECT_EQ(info.ToString(InnerLink::LinkState::DISCONNECTED), "DISCONNECTED");
    EXPECT_EQ(info.ToString(InnerLink::LinkState::CONNECTED), "CONNECTED");
    EXPECT_EQ(info.ToString(InnerLink::LinkState::CONNECTING), "CONNECTING");
    EXPECT_EQ(info.ToString(InnerLink::LinkState::DISCONNECTING), "DISCONNECTING");
}

/*
 * @tc.name: SetKeepaliveState
 * @tc.desc: test SetKeepaliveState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, SetKeepaliveState, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.SetKeepaliveState(false), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: CheckOnlyVirtualLinks
 * @tc.desc: test CheckOnlyVirtualLinks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, CheckOnlyVirtualLinks, TestSize.Level1)
{
    InnerLink info("");

    WifiDirectLink link {};
    info.GenerateLink(1, 2, link, true);
    EXPECT_EQ(info.CheckOnlyVirtualLinks(), true);
    info.RemoveId(link.linkId);

    info.GenerateLink(1, 2, link, false);
    EXPECT_EQ(info.CheckOnlyVirtualLinks(), false);
}

/*
 * @tc.name: ConstructorWithRemoteMac
 * @tc.desc: test constructor with remote MAC address
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, ConstructorWithRemoteMac, TestSize.Level1)
{
    std::string remoteMac = "AA:BB:CC:DD:EE:FF";
    InnerLink link(remoteMac);
    EXPECT_EQ(link.GetRemoteBaseMac(), remoteMac);
}

/*
 * @tc.name: ConstructorWithTypeAndDeviceId
 * @tc.desc: test constructor with link type and device ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, ConstructorWithTypeAndDeviceId, TestSize.Level1)
{
    std::string deviceId = "0123456789ABCDEF";
    InnerLink link(InnerLink::LinkType::HML, deviceId);
    EXPECT_EQ(link.GetLinkType(), InnerLink::LinkType::HML);
    EXPECT_EQ(link.GetRemoteDeviceId(), deviceId);
}

/*
 * @tc.name: LinkPowerModeTest
 * @tc.desc: test link power mode set and get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, LinkPowerModeTest, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.GetLinkPowerMode(), DEFAULT_POWER);

    info.SetLinkPowerMode(LOW_POWER);
    EXPECT_EQ(info.GetLinkPowerMode(), LOW_POWER);

    info.SetLinkPowerMode(INVALID_POWER);
    EXPECT_EQ(info.GetLinkPowerMode(), INVALID_POWER);
}

/*
 * @tc.name: CustomPortTest
 * @tc.desc: test custom port set and get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, CustomPortTest, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.GetLocalCustomPort(), -1);
    EXPECT_EQ(info.GetRemoteCustomPort(), -1);

    info.SetLocalCustomPort(9999);
    EXPECT_EQ(info.GetLocalCustomPort(), 9999);

    info.SetRemoteCustomPort(8888);
    EXPECT_EQ(info.GetRemoteCustomPort(), 8888);
}

/*
 * @tc.name: Ipv6AddressTest
 * @tc.desc: test IPv6 address set and get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, Ipv6AddressTest, TestSize.Level1)
{
    InnerLink info("");
    std::string ipv6Local = "2001:db8::1";
    std::string ipv6Remote = "2001:db8::2";

    info.SetLocalIpv6(ipv6Local);
    EXPECT_EQ(info.GetLocalIpv6(), ipv6Local);

    info.SetRemoteIpv6(ipv6Remote);
    EXPECT_EQ(info.GetRemoteIpv6(), ipv6Remote);
}

/*
 * @tc.name: NegotiateChannelTest
 * @tc.desc: test negotiate channel set and get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, NegotiateChannelTest, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.GetNegotiateChannel(), nullptr);

    // Test setting null channel
    info.SetNegotiateChannel(nullptr);
    EXPECT_EQ(info.GetNegotiateChannel(), nullptr);
}

/*
 * @tc.name: GenerateLinkWithVirtualFlag
 * @tc.desc: test GenerateLink with virtual link flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, GenerateLinkWithVirtualFlag, TestSize.Level1)
{
    InnerLink info("");
    WifiDirectLink link1 {};
    info.GenerateLink(100, 200, link1, true, true);
    EXPECT_EQ(info.IsContainId(link1.linkId), true);
    EXPECT_EQ(info.GetReference(), 1);

    WifiDirectLink link2 {};
    info.GenerateLink(101, 201, link2, true, false);
    EXPECT_EQ(info.IsContainId(link2.linkId), true);
    EXPECT_EQ(info.GetReference(), 2);

    info.RemoveId(link1.linkId);
    EXPECT_EQ(info.IsContainId(link1.linkId), false);
    EXPECT_EQ(info.GetReference(), 1);
}

/*
 * @tc.name: MultipleRemoveIdTest
 * @tc.desc: test removing non-existent link ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, MultipleRemoveIdTest, TestSize.Level1)
{
    InnerLink info("");
    WifiDirectLink link {};
    info.GenerateLink(1, 2, link, false);

    // Remove same ID twice
    info.RemoveId(link.linkId);
    info.RemoveId(link.linkId);
    EXPECT_EQ(info.GetReference(), 0);
}

/*
 * @tc.name: StateTransitionTest
 * @tc.desc: test state transitions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, StateTransitionTest, TestSize.Level1)
{
    InnerLink info("");

    info.SetState(InnerLink::LinkState::DISCONNECTED);
    EXPECT_EQ(info.GetState(), InnerLink::LinkState::DISCONNECTED);

    info.SetState(InnerLink::LinkState::CONNECTING);
    EXPECT_EQ(info.GetState(), InnerLink::LinkState::CONNECTING);

    info.SetState(InnerLink::LinkState::CONNECTED);
    EXPECT_EQ(info.GetState(), InnerLink::LinkState::CONNECTED);

    info.SetState(InnerLink::LinkState::DISCONNECTING);
    EXPECT_EQ(info.GetState(), InnerLink::LinkState::DISCONNECTING);
}

/*
 * @tc.name: LinkTypeTest
 * @tc.desc: test different link types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, LinkTypeTest, TestSize.Level1)
{
    InnerLink info1("");
    info1.SetLinkType(InnerLink::LinkType::P2P);
    EXPECT_EQ(info1.GetLinkType(), InnerLink::LinkType::P2P);

    InnerLink info2("");
    info2.SetLinkType(InnerLink::LinkType::HML);
    EXPECT_EQ(info2.GetLinkType(), InnerLink::LinkType::HML);

    InnerLink info3("");
    info3.SetLinkType(InnerLink::LinkType::INVALID_TYPE);
    EXPECT_EQ(info3.GetLinkType(), InnerLink::LinkType::INVALID_TYPE);
}

/*
 * @tc.name: FrequencyBoundaryTest
 * @tc.desc: test frequency boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, FrequencyBoundaryTest, TestSize.Level1)
{
    InnerLink info("");

    info.SetFrequency(2412); // 2.4GHz channel 1
    EXPECT_EQ(info.GetFrequency(), 2412);

    info.SetFrequency(5180); // 5GHz channel 36
    EXPECT_EQ(info.GetFrequency(), 5180);

    info.SetFrequency(5945); // 6GHz
    EXPECT_EQ(info.GetFrequency(), 5945);

    info.SetFrequency(0);
    EXPECT_EQ(info.GetFrequency(), 0);

    info.SetFrequency(-1);
    EXPECT_EQ(info.GetFrequency(), -1);
}

/*
 * @tc.name: PortBoundaryTest
 * @tc.desc: test port boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, PortBoundaryTest, TestSize.Level1)
{
    InnerLink info("");

    info.SetLocalPort(0);
    EXPECT_EQ(info.GetLocalPort(), 0);

    info.SetLocalPort(65535);
    EXPECT_EQ(info.GetLocalPort(), 65535);

    info.SetRemotePort(80);
    EXPECT_EQ(info.GetRemotePort(), 80);

    info.SetRemotePort(443);
    EXPECT_EQ(info.GetRemotePort(), 443);
}

/*
 * @tc.name: MacAddressFormatTest
 * @tc.desc: test various MAC address formats
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, MacAddressFormatTest, TestSize.Level1)
{
    InnerLink info("");

    // Standard MAC format
    info.SetLocalBaseMac("AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(info.GetLocalBaseMac(), "AA:BB:CC:DD:EE:FF");

    info.SetRemoteBaseMac("11:22:33:44:55:66");
    EXPECT_EQ(info.GetRemoteBaseMac(), "11:22:33:44:55:66");

    // Dynamic MAC
    info.SetLocalDynamicMac("00:11:22:33:44:55");
    EXPECT_EQ(info.GetLocalDynamicMac(), "00:11:22:33:44:55");

    info.SetRemoteDynamicMac("66:77:88:99:AA:BB");
    EXPECT_EQ(info.GetRemoteDynamicMac(), "66:77:88:99:AA:BB");
}

/*
 * @tc.name: IpAddressFormatTest
 * @tc.desc: test various IP address formats
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, IpAddressFormatTest, TestSize.Level1)
{
    InnerLink info("");

    info.SetLocalIpv4("192.168.1.1");
    EXPECT_EQ(info.GetLocalIpv4(), "192.168.1.1");

    info.SetRemoteIpv4("10.0.0.1");
    EXPECT_EQ(info.GetRemoteIpv4(), "10.0.0.1");

    info.SetLocalIpv4("172.30.1.100");
    EXPECT_EQ(info.GetLocalIpv4(), "172.30.1.100");
}

/*
 * @tc.name: BeingUsedByRemoteTest
 * @tc.desc: test being used by remote flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, BeingUsedByRemoteTest, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.IsBeingUsedByRemote(), false);

    info.SetBeingUsedByRemote(true);
    EXPECT_EQ(info.IsBeingUsedByRemote(), true);

    info.SetBeingUsedByRemote(false);
    EXPECT_EQ(info.IsBeingUsedByRemote(), false);
}

/*
 * @tc.name: PtkFlagTest
 * @tc.desc: test PTK (Pairwise Transient Key) flags
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, PtkFlagTest, TestSize.Level1)
{
    InnerLink info("");

    info.SetPtk(true);
    EXPECT_EQ(info.HasPtk(), true);

    info.SetPtk(false);
    EXPECT_EQ(info.HasPtk(), false);

    info.SetNewPtkFrame(true);
    EXPECT_EQ(info.GetNewPtkFrame(), true);

    info.SetNewPtkFrame(false);
    EXPECT_EQ(info.GetNewPtkFrame(), false);
}

/*
 * @tc.name: LegacyReusedFlagTest
 * @tc.desc: test legacy reused flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, LegacyReusedFlagTest, TestSize.Level1)
{
    InnerLink info("");

    info.SetLegacyReused(true);
    EXPECT_EQ(info.GetLegacyReused(), true);

    info.SetLegacyReused(false);
    EXPECT_EQ(info.GetLegacyReused(), false);
}

/*
 * @tc.name: ListenerModuleTest
 * @tc.desc: test listener module set and get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, ListenerModuleTest, TestSize.Level1)
{
    InnerLink info("");

    info.SetListenerModule(ListenerModule::LISTENER_MODULE_AUTH);
    EXPECT_EQ(info.GetListenerModule(), ListenerModule::LISTENER_MODULE_AUTH);

    info.SetListenerModule(ListenerModule::LISTENER_MODULE_P2P);
    EXPECT_EQ(info.GetListenerModule(), ListenerModule::LISTENER_MODULE_P2P);

    info.SetListenerModule(ListenerModule::LISTENER_MODULE_DYNAMIC_START);
    EXPECT_EQ(info.GetListenerModule(), ListenerModule::LISTENER_MODULE_DYNAMIC_START);
}

/*
 * @tc.name: ReferenceCountTest
 * @tc.desc: test reference count management
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, ReferenceCountTest, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.GetReference(), 0);

    WifiDirectLink link1 {};
    info.GenerateLink(1, 100, link1, false);
    EXPECT_EQ(info.GetReference(), 1);

    WifiDirectLink link2 {};
    info.GenerateLink(2, 200, link2, false);
    EXPECT_EQ(info.GetReference(), 2);

    info.RemoveId(link1.linkId);
    EXPECT_EQ(info.GetReference(), 1);

    info.RemoveId(link2.linkId);
    EXPECT_EQ(info.GetReference(), 0);
}

/*
 * @tc.name: DeviceIdTest
 * @tc.desc: test device ID operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, DeviceIdTest, TestSize.Level1)
{
    InnerLink info("");
    std::string deviceId = "7001005458323933328a013ce3153800";

    info.SetRemoteDeviceId(deviceId);
    EXPECT_EQ(info.GetRemoteDeviceId(), deviceId);

    info.SetRemoteDeviceId("");
    EXPECT_EQ(info.GetRemoteDeviceId(), "");
}

/*
 * @tc.name: InterfaceNameTest
 * @tc.desc: test interface name operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, InterfaceNameTest, TestSize.Level1)
{
    InnerLink info("");

    info.SetLocalInterface(IF_NAME_P2P);
    EXPECT_EQ(info.GetLocalInterface(), IF_NAME_P2P);

    info.SetLocalInterface(IF_NAME_HML);
    EXPECT_EQ(info.GetLocalInterface(), IF_NAME_HML);

    info.SetRemoteInterface("p2p-p2p0-1");
    EXPECT_EQ(info.GetRemoteInterface(), "p2p-p2p0-1");
}

/*
 * @tc.name: ProtectedStateAfterStateChange
 * @tc.desc: test protected state after state changes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, ProtectedStateAfterStateChange, TestSize.Level1)
{
    InnerLink info("");

    info.SetState(InnerLink::LinkState::CONNECTED);
    EXPECT_EQ(info.IsProtected(), true);

    info.SetState(InnerLink::LinkState::DISCONNECTED);
    // Sleep to exceed PROTECT_DURATION_MS
    sleep(PROTECT_DURATION_MS / 1000 + 1);
    EXPECT_EQ(info.IsProtected(), false);
}

} // namespace OHOS::SoftBus
