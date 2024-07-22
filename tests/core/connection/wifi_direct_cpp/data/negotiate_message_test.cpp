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

#include <gtest/gtest.h>
#include "data/link_info.h"
#include "data/negotiate_message.h"
#include "protocol/wifi_direct_protocol_factory.h"
using namespace testing::ext;

namespace OHOS::SoftBus {
class NegotiateMessageTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: SetAndGetBool
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, SetAndGetBool, TestSize.Level1)
{
    NegotiateMessage msg;
    EXPECT_EQ(msg.GetIsModeStrict(), false);
    msg.SetIsModeStrict(true);
    EXPECT_EQ(msg.GetIsModeStrict(), true);

    EXPECT_EQ(msg.GetIsBridgeSupported(), false);
    msg.SetIsBridgeSupported(true);
    EXPECT_EQ(msg.GetIsBridgeSupported(), true);

    EXPECT_EQ(msg.GetIsProxyEnable(), false);
    msg.SetIsProxyEnable(true);
    EXPECT_EQ(msg.GetIsProxyEnable(), true);
}

/*
 * @tc.name: SetAndGetInt
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, SetAndGetInt, TestSize.Level1)
{
    NegotiateMessage msg;
    EXPECT_EQ(msg.GetMessageType(), NegotiateMessageType::CMD_INVALID);
    msg.SetMessageType(NegotiateMessageType::CMD_CONN_V2_REQ_1);
    EXPECT_EQ(msg.GetMessageType(), NegotiateMessageType::CMD_CONN_V2_REQ_1);

    EXPECT_EQ(msg.GetSessionId(), NegotiateMessage::SESSION_ID_INVALID);
    msg.SetSessionId(100);
    EXPECT_EQ(msg.GetSessionId(), 100);

    EXPECT_EQ(msg.GetPreferLinkMode(), LinkInfo::LinkMode::INVALID);
    msg.SetPreferLinkMode(LinkInfo::LinkMode::HML);
    EXPECT_EQ(msg.GetPreferLinkMode(), LinkInfo::LinkMode::HML);

    EXPECT_EQ(msg.GetPreferLinkBandWidth(), 0);
    msg.SetPreferLinkBandWidth(80);
    EXPECT_EQ(msg.GetPreferLinkBandWidth(), 80);

    EXPECT_EQ(msg.GetResultCode(), NegotiateMessage::RESULT_CODE_INVALID);
    msg.SetResultCode(204010);
    EXPECT_EQ(msg.GetResultCode(), 204010);
}

/*
 * @tc.name: SetAndGetString
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, SetAndGetString, TestSize.Level1)
{
    NegotiateMessage msg;
    EXPECT_EQ(msg.GetRemoteDeviceId(), "");
    msg.SetRemoteDeviceId("abcdef");
    EXPECT_EQ(msg.GetRemoteDeviceId(), "abcdef");

    EXPECT_EQ(msg.Get5GChannelList(), "");
    msg.Set5GChannelList("36#40#60");
    EXPECT_EQ(msg.Get5GChannelList(), "36#40#60");

    EXPECT_EQ(msg.Get5GChannelScore(), "");
    msg.Set5GChannelScore("90#10#0");
    EXPECT_EQ(msg.Get5GChannelScore(), "90#10#0");
}

/*
 * @tc.name: SetAndGetByteArray
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, SetAndGetByteArray, TestSize.Level1)
{
    NegotiateMessage msg;
    EXPECT_EQ(msg.GetWifiConfigInfo().empty(), true);
    std::vector<uint8_t> wifiConfig { 0x01, 0x02, 0x03, 0x04 };
    msg.SetWifiConfigInfo(wifiConfig);
    EXPECT_EQ(msg.GetWifiConfigInfo(), wifiConfig);
}

/*
 * @tc.name: SetAndGetIpv4InfoArray
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, SetAndGetIpv4InfoArray, TestSize.Level1)
{
    NegotiateMessage msg;
    EXPECT_EQ(msg.GetIpv4InfoArray().empty(), true);
    std::vector<Ipv4Info> ipv4Array { Ipv4Info("172.30.1.1"), Ipv4Info("172.30.1.2") };
    msg.SetIpv4InfoArray(ipv4Array);
    EXPECT_EQ(msg.GetIpv4InfoArray(), ipv4Array);
}

/*
 * @tc.name: SetAndGetInterfaceInfoArray
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, SetAndGetInterfaceInfoArray, TestSize.Level1)
{
    NegotiateMessage msg;
    EXPECT_EQ(msg.GetInterfaceInfoArray().empty(), true);
    InterfaceInfo info1;
    InterfaceInfo info2;
    std::vector<InterfaceInfo> infoArray { InterfaceInfo(), InterfaceInfo() };
    msg.SetInterfaceInfoArray(infoArray);
    EXPECT_EQ(msg.GetInterfaceInfoArray().size(), infoArray.size());
}

/*
 * @tc.name: SetAndGetByteArray
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, SetAndGetLinkInfo, TestSize.Level1)
{
    NegotiateMessage msg;
    EXPECT_EQ(msg.GetLinkInfo().GetCenter20M(), 0);
    LinkInfo linkInfo;
    linkInfo.SetCenter20M(5180);
    linkInfo.SetLocalBaseMac("01:02:03:04:05:06");
    msg.SetLinkInfo(linkInfo);
    EXPECT_EQ(msg.GetLinkInfo().GetCenter20M(), 5180);
    EXPECT_EQ(msg.GetLinkInfo().GetLocalBaseMac(), "01:02:03:04:05:06");
}

/*
 * @tc.name: MarshallingAndUnmarshalling
 * @tc.desc: marshalling and unmarshalling of tlv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, MarshallingAndUnmarshallingOfTlv, TestSize.Level1)
{
    NegotiateMessage msg1;
    msg1.SetSessionId(1);
    msg1.SetIsModeStrict(true);
    msg1.SetMessageType(NegotiateMessageType::CMD_CONN_V2_REQ_1);
    msg1.SetIpv4InfoArray({ Ipv4Info("172.30.1.1"), Ipv4Info("172.30.2.1") });
    LinkInfo linkInfo1;
    linkInfo1.SetCenter20M(5180);
    linkInfo1.SetLocalBaseMac("01:02:03:04:05:06");
    msg1.SetLinkInfo(linkInfo1);

    auto protocol1 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol1->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> output;
    msg1.Marshalling(*protocol1, output);
    std::cout << output.size() << std::endl;

    NegotiateMessage msg2;
    auto protocol2 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol2->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    msg2.Unmarshalling(*protocol2, output);

    LinkInfo linkInfo2 = msg2.GetLinkInfo();
    EXPECT_EQ(msg1.GetSessionId(), msg2.GetSessionId());
    EXPECT_EQ(msg1.GetMessageType(), msg2.GetMessageType());
    EXPECT_EQ(msg1.GetIsModeStrict(), msg2.GetIsModeStrict());
    EXPECT_EQ(linkInfo1.GetCenter20M(), linkInfo2.GetCenter20M());
    EXPECT_EQ(linkInfo1.GetLocalBaseMac(), linkInfo2.GetLocalBaseMac());

    std::vector<Ipv4Info> ipv4Array1 = msg1.GetIpv4InfoArray();
    std::vector<Ipv4Info> ipv4Array2 = msg2.GetIpv4InfoArray();
    EXPECT_EQ(linkInfo1.GetCenter20M(), linkInfo2.GetCenter20M());
    EXPECT_EQ(linkInfo1.GetLocalBaseMac(), linkInfo2.GetLocalBaseMac());

    NegotiateMessage msg3;
    auto protocol3 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol1->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> output3;
    msg1.Marshalling(*protocol3, output3);

    NegotiateMessage msg4;
    auto protocol4 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol2->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    msg2.Unmarshalling(*protocol4, output3);
}

/*
 * @tc.name: SetAndGetLegacyP2p01
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, SetAndGetLegacyP2p01, TestSize.Level1)
{
    NegotiateMessage msg;
    EXPECT_EQ(msg.GetLegacyP2pGcChannelList(), "");
    msg.SetLegacyP2pGcChannelList("1#2#3");
    EXPECT_EQ(msg.GetLegacyP2pGcChannelList(), "1#2#3");

    EXPECT_EQ(msg.GetLegacyP2pStationFrequency(), 0);
    msg.SetLegacyP2pStationFrequency(5180);
    EXPECT_EQ(msg.GetLegacyP2pStationFrequency(), 5180);

    EXPECT_EQ(msg.GetLegacyP2pRole(), static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_INVALID));
    msg.SetLegacyP2pRole(WifiDirectRole::WIFI_DIRECT_ROLE_HML);
    EXPECT_EQ(msg.GetLegacyP2pRole(), static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_HML));

    EXPECT_EQ(msg.GetLegacyP2pExpectedRole(), static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_INVALID));
    msg.SetLegacyP2pExpectedRole(WifiDirectRole::WIFI_DIRECT_ROLE_HML);
    EXPECT_EQ(msg.GetLegacyP2pExpectedRole(), static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_HML));

    EXPECT_EQ(msg.GetLegacyP2pVersion(), 0);
    msg.SetLegacyP2pVersion(2);
    EXPECT_EQ(msg.GetLegacyP2pVersion(), 2);

    EXPECT_EQ(msg.GetLegacyP2pGcIp(), "");
    msg.SetLegacyP2pGcIp("192.168.43.2");
    EXPECT_EQ(msg.GetLegacyP2pGcIp(), "192.168.43.2");

    EXPECT_EQ(msg.GetLegacyP2pWideBandSupported(), false);
    msg.SetLegacyP2pWideBandSupported(true);
    EXPECT_EQ(msg.GetLegacyP2pWideBandSupported(), true);

    EXPECT_EQ(msg.GetLegacyP2pGroupConfig(), "");
    msg.SetLegacyP2pGroupConfig("OHOS-1234\n00:01:02:03:04:05\n00001111\n5180");
    EXPECT_EQ(msg.GetLegacyP2pGroupConfig(), "OHOS-1234\n00:01:02:03:04:05\n00001111\n5180");
}

/*
 * @tc.name: SetAndGetLegacyP2p02
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, SetAndGetLegacyP2p02, TestSize.Level1)
{
    NegotiateMessage msg;
    EXPECT_EQ(msg.GetLegacyP2pMac(), "");
    msg.SetLegacyP2pMac("01:02:03:04:05:06");
    EXPECT_EQ(msg.GetLegacyP2pMac(), "01:02:03:04:05:06");

    EXPECT_EQ(msg.GetLegacyP2pGoIp(), "");
    msg.SetLegacyP2pGoIp("192.168.43.1");
    EXPECT_EQ(msg.GetLegacyP2pGoIp(), "192.168.43.1");

    EXPECT_EQ(msg.GetLegacyP2pGoMac(), "");
    msg.SetLegacyP2pGoMac("01:02:03:04:05:06");
    EXPECT_EQ(msg.GetLegacyP2pGoMac(), "01:02:03:04:05:06");

    EXPECT_EQ(msg.GetLegacyP2pGoPort(), 0);
    msg.SetLegacyP2pGoPort(4321);
    EXPECT_EQ(msg.GetLegacyP2pGoPort(), 4321);

    EXPECT_EQ(msg.GetLegacyP2pIp(), "");
    msg.SetLegacyP2pIp("192.168.43.4");
    EXPECT_EQ(msg.GetLegacyP2pIp(), "192.168.43.4");

    EXPECT_EQ(msg.GetLegacyP2pResult(), LegacyResult::OK);
    msg.SetLegacyP2pResult(LegacyResult::V1_ERROR_IF_NOT_AVAILABLE);
    EXPECT_EQ(msg.GetLegacyP2pResult(), LegacyResult::V1_ERROR_IF_NOT_AVAILABLE);

    EXPECT_EQ(msg.GetLegacyP2pContentType(), LegacyContentType::INVALID);
    msg.SetLegacyP2pContentType(LegacyContentType::GC_INFO);
    EXPECT_EQ(msg.GetLegacyP2pContentType(), LegacyContentType::GC_INFO);

    EXPECT_EQ(msg.GetLegacyP2pGcMac(), "");
    msg.SetLegacyP2pGcMac("01:02:03:04:05:06");
    EXPECT_EQ(msg.GetLegacyP2pGcMac(), "01:02:03:04:05:06");

    EXPECT_EQ(msg.GetLegacyP2pCommandType(), LegacyCommandType::CMD_INVALID);
    msg.SetLegacyP2pCommandType(LegacyCommandType::CMD_DISCONNECT_V1_REQ);
    EXPECT_EQ(msg.GetLegacyP2pCommandType(), LegacyCommandType::CMD_DISCONNECT_V1_REQ);
}

/*
 * @tc.name: MarshallingAndUnmarshallingOfJson
 * @tc.desc: marshalling and unmarshalling of json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, MarshallingAndUnmarshallingOfJson, TestSize.Level1)
{
    NegotiateMessage msg1;
    msg1.SetLegacyP2pCommandType(LegacyCommandType::CMD_CONN_V1_REQ);
    msg1.SetLegacyP2pContentType(LegacyContentType::GC_INFO);
    msg1.SetLegacyP2pRole(WifiDirectRole::WIFI_DIRECT_ROLE_HML);
    msg1.SetLegacyP2pGroupConfig("OHOS-1234\n00:01:02:03:04:05\n00001111\n5180");
    std::vector<uint8_t> vec = {65, 66, 67, 68, 69};
    msg1.SetWifiConfigInfo(vec);
    InterfaceInfo interfaceInfo;
    interfaceInfo.SetBandWidth(10);
    std::vector<InterfaceInfo> interfaceInfoArray;
    interfaceInfoArray.push_back(interfaceInfo);
    msg1.SetInterfaceInfoArray(interfaceInfoArray);

    auto protocol1 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::JSON);
    std::vector<uint8_t> output;
    msg1.Marshalling(*protocol1, output);

    std::string outJson;
    outJson.insert(outJson.end(), output.begin(), output.end());
    std::cout << outJson << std::endl;

    NegotiateMessage msg2;
    auto protocol2 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::JSON);
    msg2.Unmarshalling(*protocol2, output);

    EXPECT_EQ(msg1.GetLegacyP2pCommandType(), msg2.GetLegacyP2pCommandType());
    EXPECT_EQ(msg1.GetLegacyP2pContentType(), msg2.GetLegacyP2pContentType());
    EXPECT_EQ(msg1.GetLegacyP2pRole(), msg2.GetLegacyP2pRole());
    EXPECT_EQ(msg1.GetLegacyP2pGroupConfig(), msg2.GetLegacyP2pGroupConfig());
}

/*
 * @tc.name: SetAndGet
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, SetAndGetMsg, TestSize.Level1)
{
    NegotiateMessage msg;
    NegotiateMessage msg1(NegotiateMessageType::CMD_CONN_V2_REQ_1);
    NegotiateMessage msg2(LegacyCommandType::CMD_DISCONNECT_V1_REQ);
    EXPECT_EQ(msg.GetMessageType(), NegotiateMessageType::CMD_INVALID);
    msg.SetMessageType(LegacyCommandType::CMD_DISCONNECT_V1_REQ);
    msg.SetMessageType(NegotiateMessageType::CMD_V3_REQ);
    EXPECT_EQ(msg.GetMessageType(), NegotiateMessageType::CMD_V3_REQ);

    std::vector<uint8_t> ret;
    EXPECT_EQ(msg.GetExtraData(), ret);
    std::vector<uint8_t> vec = { 65, 66, 67, 68, 69 };
    msg.SetExtraData(vec);
    EXPECT_EQ(msg.GetExtraData(), vec);

    EXPECT_EQ(msg.GetChallengeCode(), 0);
    msg.SetChallengeCode(1);
    EXPECT_EQ(msg.GetChallengeCode(), 1);

    EXPECT_EQ(msg.GetLegacyP2pBridgeSupport(), false);
    msg.SetLegacyP2pBridgeSupport(true);
    EXPECT_EQ(msg.GetLegacyP2pBridgeSupport(), true);

    EXPECT_EQ(msg.GetLegacyP2pWifiConfigInfo(), "");
    msg.SetLegacyP2pWifiConfigInfo("test");
    EXPECT_EQ(msg.GetLegacyP2pWifiConfigInfo(), "test");

    EXPECT_EQ(msg.GetLegacyInterfaceName(), "");
    msg.SetLegacyInterfaceName("test");
    EXPECT_EQ(msg.GetLegacyInterfaceName(), "test");
}

/*
 * @tc.name: MessageTypeToString
 * @tc.desc: check MessageTypeToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NegotiateMessageTest, MessageTypeToString, TestSize.Level1)
{
    NegotiateMessage msg;

    msg.SetLegacyP2pCommandType(LegacyCommandType::CMD_INVALID);
    auto str = msg.MessageTypeToString();
    msg.SetMessageType(NegotiateMessageType::CMD_INVALID);
    EXPECT_EQ(str, "CMD_INVALID");
}
} // namespace OHOS::SoftBus