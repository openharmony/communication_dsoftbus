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

#define PRIVATE   PUBLIC
#define PROTECTED PUBLIC
#include "data/negotiate_message.h"
#undef protected
#undef private

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "data/interface_info.h"
#include "data/link_info.h"
#include "protocol/json_protocol.h"
#include "protocol/tlv_protocol.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "wifi_direct_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS::SoftBus {

class NegotiateMessageExtendedTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: ConstructorWithNegotiateMessageTypeTest001
 * @tc.desc: test constructor with NegotiateMessageType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, ConstructorWithNegotiateMessageTypeTest001, TestSize.Level1)
{
    NegotiateMessage msg(NegotiateMessageType::CMD_CONN_V2_REQ_1);
    EXPECT_EQ(msg.GetMessageType(), NegotiateMessageType::CMD_CONN_V2_REQ_1);
}

/*
 * @tc.name: ConstructorWithNegotiateMessageTypeTest002
 * @tc.desc: test constructor with different NegotiateMessageTypes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, ConstructorWithNegotiateMessageTypeTest002, TestSize.Level1)
{
    NegotiateMessage msg1(NegotiateMessageType::CMD_CONN_V2_REQ_2);
    EXPECT_EQ(msg1.GetMessageType(), NegotiateMessageType::CMD_CONN_V2_REQ_2);

    NegotiateMessage msg2(NegotiateMessageType::CMD_CONN_V2_REQ_3);
    EXPECT_EQ(msg2.GetMessageType(), NegotiateMessageType::CMD_CONN_V2_REQ_3);

    NegotiateMessage msg3(NegotiateMessageType::CMD_CONN_V2_RESP_1);
    EXPECT_EQ(msg3.GetMessageType(), NegotiateMessageType::CMD_CONN_V2_RESP_1);
}

/*
 * @tc.name: SetMessageTypeNegotiateTest001
 * @tc.desc: test set message type with negotiate message type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, SetMessageTypeNegotiateTest001, TestSize.Level1)
{
    NegotiateMessage msg;
    msg.SetMessageType(NegotiateMessageType::CMD_V3_REQ);
    EXPECT_EQ(msg.GetMessageType(), NegotiateMessageType::CMD_V3_REQ);
}

/*
 * @tc.name: MarshallingJsonWithAllFieldsTest001
 * @tc.desc: test JSON marshalling with all fields set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, MarshallingJsonWithAllFieldsTest001, TestSize.Level1)
{
    NegotiateMessage msg;
    msg.SetLegacyP2pCommandType(LegacyCommandType::CMD_CONN_V1_REQ);
    msg.SetLegacyP2pContentType(LegacyContentType::GO_INFO);
    msg.SetLegacyP2pRole(WifiDirectRole::WIFI_DIRECT_ROLE_GO);
    msg.SetLegacyP2pExpectedRole(WifiDirectRole::WIFI_DIRECT_ROLE_GC);
    msg.SetLegacyP2pVersion(2);
    msg.SetLegacyP2pGroupConfig("OHOS-TestSSID\n11:22:33:44:55:66\nTestPassword\n5180");
    msg.SetLegacyP2pMac("AA:BB:CC:DD:EE:FF");
    msg.SetLegacyP2pGoMac("11:22:33:44:55:66");
    msg.SetLegacyP2pGoPort(8888);
    msg.SetLegacyP2pGoIp("192.168.49.1");
    msg.SetLegacyP2pGcIp("192.168.49.2");
    msg.SetLegacyP2pGcMac("22:33:44:55:66:77");
    msg.SetLegacyP2pStationFrequency(5180);
    msg.SetLegacyP2pWideBandSupported(true);
    msg.SetLegacyP2pBridgeSupport(true);
    msg.SetLegacyP2pGcChannelList("36#40#44#48");

    auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::JSON);
    std::vector<uint8_t> output;
    int ret = msg.Marshalling(*protocol, output);

    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_FALSE(output.empty());
}

/*
 * @tc.name: MarshallingTlvWithAllFieldsTest001
 * @tc.desc: test TLV marshalling with all fields set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, MarshallingTlvWithAllFieldsTest001, TestSize.Level1)
{
    NegotiateMessage msg;
    msg.SetSessionId(12345);
    msg.SetMessageType(NegotiateMessageType::CMD_CONN_V2_REQ_1);
    msg.SetIsModeStrict(true);
    msg.SetIsBridgeSupported(true);
    msg.SetIsProxyEnable(true);
    msg.SetPreferLinkMode(LinkInfo::LinkMode::HML);
    msg.SetPreferLinkBandWidth(160);
    msg.SetRemoteDeviceId("test_remote_device_id");
    msg.Set5GChannelList("36#40#44#48#149#153");
    msg.Set5GChannelScore("100#90#80#70#60#50");
    msg.SetResultCode(0);
    msg.SetChallengeCode(9876);

    LinkInfo linkInfo;
    linkInfo.SetCenter20M(5180);
    linkInfo.SetLocalBaseMac("AA:BB:CC:DD:EE:FF");
    linkInfo.SetRemoteBaseMac("11:22:33:44:55:66");
    msg.SetLinkInfo(linkInfo);

    std::vector<Ipv4Info> ipv4Array = { Ipv4Info("172.30.1.1"), Ipv4Info("172.30.1.2") };
    msg.SetIpv4InfoArray(ipv4Array);

    std::vector<uint8_t> wifiConfig = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    msg.SetWifiConfigInfo(wifiConfig);

    auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> output;
    int ret = msg.Marshalling(*protocol, output);

    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_FALSE(output.empty());
}

/*
 * @tc.name: UnmarshallingTlvWithAllFieldsTest001
 * @tc.desc: test TLV unmarshalling restores all fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, UnmarshallingTlvWithAllFieldsTest001, TestSize.Level1)
{
    NegotiateMessage msg1;
    msg1.SetSessionId(11111);
    msg1.SetMessageType(NegotiateMessageType::CMD_CONN_V2_REQ_2);
    msg1.SetIsModeStrict(true);
    msg1.SetPreferLinkBandWidth(80);
    msg1.SetRemoteDeviceId("device_id_test");

    auto protocol1 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol1->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> output;
    msg1.Marshalling(*protocol1, output);

    NegotiateMessage msg2;
    auto protocol2 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol2->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    int ret = msg2.Unmarshalling(*protocol2, output);

    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(msg2.GetSessionId(), 11111);
    EXPECT_EQ(msg2.GetMessageType(), NegotiateMessageType::CMD_CONN_V2_REQ_2);
    EXPECT_TRUE(msg2.GetIsModeStrict());
    EXPECT_EQ(msg2.GetPreferLinkBandWidth(), 80);
}

/*
 * @tc.name: MessageTypeToStringTest001
 * @tc.desc: test message type to string for various types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, MessageTypeToStringTest001, TestSize.Level1)
{
    NegotiateMessage msg1;
    msg1.SetMessageType(NegotiateMessageType::CMD_CONN_V2_REQ_1);
    EXPECT_FALSE(msg1.MessageTypeToString().empty());

    NegotiateMessage msg2;
    msg2.SetMessageType(NegotiateMessageType::CMD_CONN_V2_RESP_1);
    EXPECT_FALSE(msg2.MessageTypeToString().empty());

    NegotiateMessage msg3;
    msg3.SetMessageType(NegotiateMessageType::CMD_V3_REQ);
    EXPECT_FALSE(msg3.MessageTypeToString().empty());
}

/*
 * @tc.name: MessageTypeToStringLegacyTest001
 * @tc.desc: test message type to string for legacy types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, MessageTypeToStringLegacyTest001, TestSize.Level1)
{
    NegotiateMessage msg1;
    msg1.SetLegacyP2pCommandType(LegacyCommandType::CMD_CONN_V1_REQ);
    EXPECT_FALSE(msg1.MessageTypeToString().empty());

    NegotiateMessage msg2;
    msg2.SetLegacyP2pCommandType(LegacyCommandType::CMD_DISCONNECT_V1_REQ);
    EXPECT_FALSE(msg2.MessageTypeToString().empty());
}

/*
 * @tc.name: SetAndGetExtraDataTest001
 * @tc.desc: test set and get extra data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, SetAndGetExtraDataTest001, TestSize.Level1)
{
    NegotiateMessage msg;
    std::vector<uint8_t> extraData = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
    msg.SetExtraData(extraData);

    auto result = msg.GetExtraData();
    EXPECT_EQ(result.size(), 6);
    EXPECT_EQ(result[0], 0x10);
    EXPECT_EQ(result[5], 0x60);
}

/*
 * @tc.name: SetAndGetChallengeCodeTest001
 * @tc.desc: test set and get challenge code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, SetAndGetChallengeCodeTest001, TestSize.Level1)
{
    NegotiateMessage msg;
    EXPECT_EQ(msg.GetChallengeCode(), 0);

    msg.SetChallengeCode(123456789);
    EXPECT_EQ(msg.GetChallengeCode(), 123456789);

    msg.SetChallengeCode(0);
    EXPECT_EQ(msg.GetChallengeCode(), 0);
}

/*
 * @tc.name: SetAndGetLegacyP2pWifiConfigInfoTest001
 * @tc.desc: test set and get legacy p2p wifi config info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, SetAndGetLegacyP2pWifiConfigInfoTest001, TestSize.Level1)
{
    NegotiateMessage msg;
    EXPECT_TRUE(msg.GetLegacyP2pWifiConfigInfo().empty());

    msg.SetLegacyP2pWifiConfigInfo("test_wifi_config_info");
    EXPECT_EQ(msg.GetLegacyP2pWifiConfigInfo(), "test_wifi_config_info");
}

/*
 * @tc.name: SetAndGetLegacyInterfaceNameTest001
 * @tc.desc: test set and get legacy interface name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, SetAndGetLegacyInterfaceNameTest001, TestSize.Level1)
{
    NegotiateMessage msg;
    EXPECT_TRUE(msg.GetLegacyInterfaceName().empty());

    msg.SetLegacyInterfaceName("p2p-wlan0-0");
    EXPECT_EQ(msg.GetLegacyInterfaceName(), "p2p-wlan0-0");
}

/*
 * @tc.name: InterfaceInfoArrayMarshallingTest001
 * @tc.desc: test interface info array marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, InterfaceInfoArrayMarshallingTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    InterfaceInfo info1;
    info1.SetName("interface1");
    info1.SetBandWidth(80);
    info1.SetCenter20M(36);

    InterfaceInfo info2;
    info2.SetName("interface2");
    info2.SetBandWidth(160);
    info2.SetCenter20M(149);

    std::vector<InterfaceInfo> infoArray = { info1, info2 };
    msg.SetInterfaceInfoArray(infoArray);

    auto result = msg.GetInterfaceInfoArray();
    EXPECT_EQ(result.size(), 2);
}

/*
 * @tc.name: Ipv4InfoArrayMarshallingTest001
 * @tc.desc: test IPv4 info array marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, Ipv4InfoArrayMarshallingTest001, TestSize.Level1)
{
    NegotiateMessage msg1;
    std::vector<Ipv4Info> ipv4Array = { Ipv4Info("192.168.1.1"), Ipv4Info("192.168.1.2"), Ipv4Info("192.168.1.3") };
    msg1.SetIpv4InfoArray(ipv4Array);

    auto protocol1 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol1->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> output;
    msg1.Marshalling(*protocol1, output);

    NegotiateMessage msg2;
    auto protocol2 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol2->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    msg2.Unmarshalling(*protocol2, output);

    auto result = msg2.GetIpv4InfoArray();
    EXPECT_EQ(result.size(), 3);
}

/*
 * @tc.name: LinkInfoMarshallingTest001
 * @tc.desc: test link info marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, LinkInfoMarshallingTest001, TestSize.Level1)
{
    NegotiateMessage msg1;
    LinkInfo linkInfo;
    linkInfo.SetCenter20M(5180);
    linkInfo.SetLocalBaseMac("AA:BB:CC:DD:EE:FF");
    linkInfo.SetRemoteBaseMac("11:22:33:44:55:66");
    linkInfo.SetBandWidth(80);
    linkInfo.SetIsClient(true);
    msg1.SetLinkInfo(linkInfo);

    auto protocol1 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol1->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> output;
    msg1.Marshalling(*protocol1, output);

    NegotiateMessage msg2;
    auto protocol2 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol2->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    msg2.Unmarshalling(*protocol2, output);

    auto result = msg2.GetLinkInfo();
    EXPECT_EQ(result.GetCenter20M(), 5180);
    EXPECT_EQ(result.GetLocalBaseMac(), "AA:BB:CC:DD:EE:FF");
}

/*
 * @tc.name: WifiConfigInfoMarshallingTest001
 * @tc.desc: test wifi config info marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, WifiConfigInfoMarshallingTest001, TestSize.Level1)
{
    NegotiateMessage msg1;
    std::vector<uint8_t> wifiConfig = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    msg1.SetWifiConfigInfo(wifiConfig);

    auto protocol1 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol1->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> output;
    msg1.Marshalling(*protocol1, output);

    NegotiateMessage msg2;
    auto protocol2 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol2->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    msg2.Unmarshalling(*protocol2, output);

    auto result = msg2.GetWifiConfigInfo();
    EXPECT_EQ(result.size(), 6);
    EXPECT_EQ(result[0], 0xAA);
}

/*
 * @tc.name: EmptyMarshallingTest001
 * @tc.desc: test marshalling with empty message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, EmptyMarshallingTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> output;
    int ret = msg.Marshalling(*protocol, output);

    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: EmptyUnmarshallingTest001
 * @tc.desc: test unmarshalling with empty input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, EmptyUnmarshallingTest001, TestSize.Level1)
{
    NegotiateMessage msg;
    std::vector<uint8_t> emptyInput;

    auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    int ret = msg.Unmarshalling(*protocol, emptyInput);

    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LegacyResultTypesTest001
 * @tc.desc: test all legacy result types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, LegacyResultTypesTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    msg.SetLegacyP2pResult(LegacyResult::OK);
    EXPECT_EQ(msg.GetLegacyP2pResult(), LegacyResult::OK);

    msg.SetLegacyP2pResult(LegacyResult::V1_ERROR_IF_NOT_AVAILABLE);
    EXPECT_EQ(msg.GetLegacyP2pResult(), LegacyResult::V1_ERROR_IF_NOT_AVAILABLE);

    msg.SetLegacyP2pResult(LegacyResult::V1_ERROR_CONNECTED_WITH_MISMATCHED_ROLE);
    EXPECT_EQ(msg.GetLegacyP2pResult(), LegacyResult::V1_ERROR_CONNECTED_WITH_MISMATCHED_ROLE);
}

/*
 * @tc.name: LegacyContentTypesTest001
 * @tc.desc: test all legacy content types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, LegacyContentTypesTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    msg.SetLegacyP2pContentType(LegacyContentType::INVALID);
    EXPECT_EQ(msg.GetLegacyP2pContentType(), LegacyContentType::INVALID);

    msg.SetLegacyP2pContentType(LegacyContentType::GO_INFO);
    EXPECT_EQ(msg.GetLegacyP2pContentType(), LegacyContentType::GO_INFO);

    msg.SetLegacyP2pContentType(LegacyContentType::GC_INFO);
    EXPECT_EQ(msg.GetLegacyP2pContentType(), LegacyContentType::GC_INFO);

    msg.SetLegacyP2pContentType(LegacyContentType::RESULT);
    EXPECT_EQ(msg.GetLegacyP2pContentType(), LegacyContentType::RESULT);
}

/*
 * @tc.name: WifiDirectRoleTypesTest001
 * @tc.desc: test all wifi direct role types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, WifiDirectRoleTypesTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    msg.SetLegacyP2pRole(WifiDirectRole::WIFI_DIRECT_ROLE_INVALID);
    EXPECT_EQ(msg.GetLegacyP2pRole(), static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_INVALID));

    msg.SetLegacyP2pRole(WifiDirectRole::WIFI_DIRECT_ROLE_NONE);
    EXPECT_EQ(msg.GetLegacyP2pRole(), static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_NONE));

    msg.SetLegacyP2pRole(WifiDirectRole::WIFI_DIRECT_ROLE_GO);
    EXPECT_EQ(msg.GetLegacyP2pRole(), static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_GO));

    msg.SetLegacyP2pRole(WifiDirectRole::WIFI_DIRECT_ROLE_GC);
    EXPECT_EQ(msg.GetLegacyP2pRole(), static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_GC));

    msg.SetLegacyP2pRole(WifiDirectRole::WIFI_DIRECT_ROLE_HML);
    EXPECT_EQ(msg.GetLegacyP2pRole(), static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_HML));
}

/*
 * @tc.name: PreferLinkModeTest001
 * @tc.desc: test all prefer link modes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, PreferLinkModeTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    msg.SetPreferLinkMode(LinkInfo::LinkMode::INVALID);
    EXPECT_EQ(msg.GetPreferLinkMode(), LinkInfo::LinkMode::INVALID);

    msg.SetPreferLinkMode(LinkInfo::LinkMode::NONE);
    EXPECT_EQ(msg.GetPreferLinkMode(), LinkInfo::LinkMode::NONE);

    msg.SetPreferLinkMode(LinkInfo::LinkMode::GO);
    EXPECT_EQ(msg.GetPreferLinkMode(), LinkInfo::LinkMode::GO);

    msg.SetPreferLinkMode(LinkInfo::LinkMode::GC);
    EXPECT_EQ(msg.GetPreferLinkMode(), LinkInfo::LinkMode::GC);

    msg.SetPreferLinkMode(LinkInfo::LinkMode::HML);
    EXPECT_EQ(msg.GetPreferLinkMode(), LinkInfo::LinkMode::HML);
}

/*
 * @tc.name: SessionIdBoundaryTest001
 * @tc.desc: test session id boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, SessionIdBoundaryTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    msg.SetSessionId(0);
    EXPECT_EQ(msg.GetSessionId(), 0);

    msg.SetSessionId(INT32_MAX);
    EXPECT_EQ(msg.GetSessionId(), INT32_MAX);

    msg.SetSessionId(NegotiateMessage::SESSION_ID_INVALID);
    EXPECT_EQ(msg.GetSessionId(), NegotiateMessage::SESSION_ID_INVALID);
}

/*
 * @tc.name: ResultCodeBoundaryTest001
 * @tc.desc: test result code boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, ResultCodeBoundaryTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    msg.SetResultCode(0);
    EXPECT_EQ(msg.GetResultCode(), 0);

    msg.SetResultCode(INT32_MAX);
    EXPECT_EQ(msg.GetResultCode(), INT32_MAX);

    msg.SetResultCode(INT32_MIN);
    EXPECT_EQ(msg.GetResultCode(), INT32_MIN);
}

/*
 * @tc.name: LegacyP2pIpFieldsTest001
 * @tc.desc: test legacy p2p ip fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, LegacyP2pIpFieldsTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    msg.SetLegacyP2pIp("192.168.1.100");
    EXPECT_EQ(msg.GetLegacyP2pIp(), "192.168.1.100");

    msg.SetLegacyP2pGoIp("192.168.1.1");
    EXPECT_EQ(msg.GetLegacyP2pGoIp(), "192.168.1.1");

    msg.SetLegacyP2pGcIp("192.168.1.2");
    EXPECT_EQ(msg.GetLegacyP2pGcIp(), "192.168.1.2");
}

/*
 * @tc.name: LegacyP2pMacFieldsTest001
 * @tc.desc: test legacy p2p mac fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, LegacyP2pMacFieldsTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    msg.SetLegacyP2pMac("AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(msg.GetLegacyP2pMac(), "AA:BB:CC:DD:EE:FF");

    msg.SetLegacyP2pGoMac("11:22:33:44:55:66");
    EXPECT_EQ(msg.GetLegacyP2pGoMac(), "11:22:33:44:55:66");

    msg.SetLegacyP2pGcMac("77:88:99:AA:BB:CC");
    EXPECT_EQ(msg.GetLegacyP2pGcMac(), "77:88:99:AA:BB:CC");
}

/*
 * @tc.name: LegacyP2pPortTest001
 * @tc.desc: test legacy p2p port
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, LegacyP2pPortTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    msg.SetLegacyP2pGoPort(0);
    EXPECT_EQ(msg.GetLegacyP2pGoPort(), 0);

    msg.SetLegacyP2pGoPort(65535);
    EXPECT_EQ(msg.GetLegacyP2pGoPort(), 65535);

    msg.SetLegacyP2pGoPort(8080);
    EXPECT_EQ(msg.GetLegacyP2pGoPort(), 8080);
}

/*
 * @tc.name: PreferLinkBandWidthTest001
 * @tc.desc: test prefer link bandwidth values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, PreferLinkBandWidthTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    msg.SetPreferLinkBandWidth(20);
    EXPECT_EQ(msg.GetPreferLinkBandWidth(), 20);

    msg.SetPreferLinkBandWidth(40);
    EXPECT_EQ(msg.GetPreferLinkBandWidth(), 40);

    msg.SetPreferLinkBandWidth(80);
    EXPECT_EQ(msg.GetPreferLinkBandWidth(), 80);

    msg.SetPreferLinkBandWidth(160);
    EXPECT_EQ(msg.GetPreferLinkBandWidth(), 160);
}

/*
 * @tc.name: Channel5GFieldsTest001
 * @tc.desc: test 5G channel fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, Channel5GFieldsTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    msg.Set5GChannelList("36#40#44#48#149#153#157#161#165");
    EXPECT_EQ(msg.Get5GChannelList(), "36#40#44#48#149#153#157#161#165");

    msg.Set5GChannelScore("100#90#80#70#60#50#40#30#20");
    EXPECT_EQ(msg.Get5GChannelScore(), "100#90#80#70#60#50#40#30#20");
}

/*
 * @tc.name: MultipleSetGetCycleTest001
 * @tc.desc: test multiple set/get cycles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, MultipleSetGetCycleTest001, TestSize.Level1)
{
    NegotiateMessage msg;

    for (int i = 0; i < 10; i++) {
        msg.SetSessionId(i);
        EXPECT_EQ(msg.GetSessionId(), i);
    }

    for (int i = 0; i < 10; i++) {
        msg.SetResultCode(i * 1000);
        EXPECT_EQ(msg.GetResultCode(), i * 1000);
    }
}

/*
 * @tc.name: JsonMarshallingUnmarshallingCycleTest001
 * @tc.desc: test JSON marshalling/unmarshalling cycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageExtendedTest, JsonMarshallingUnmarshallingCycleTest001, TestSize.Level1)
{
    NegotiateMessage msg1;
    msg1.SetLegacyP2pCommandType(LegacyCommandType::CMD_CONN_V1_REQ);
    msg1.SetLegacyP2pRole(WifiDirectRole::WIFI_DIRECT_ROLE_GO);
    msg1.SetLegacyP2pGoPort(9999);
    msg1.SetLegacyP2pGoIp("10.0.0.1");
    msg1.SetLegacyP2pGroupConfig("TestSSID\n00:11:22:33:44:55\nPassword\n5180");

    auto protocol1 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::JSON);
    std::vector<uint8_t> output;
    msg1.Marshalling(*protocol1, output);

    NegotiateMessage msg2;
    auto protocol2 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::JSON);
    msg2.Unmarshalling(*protocol2, output);

    EXPECT_EQ(msg2.GetLegacyP2pCommandType(), LegacyCommandType::CMD_CONN_V1_REQ);
    EXPECT_EQ(msg2.GetLegacyP2pRole(), static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_GO));
    EXPECT_EQ(msg2.GetLegacyP2pGoPort(), 9999);
}

} // namespace OHOS::SoftBus
