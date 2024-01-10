/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <cstdio>
#include <cstring>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <securec.h>

#include "common_list.h"
#include "wifi_direct_processor.h"
#include "wifi_direct_types.h"
#include "p2p_v1_processor.h"
#include "default_negotiate_channel_mock.h"
#include "wifi_direct_negotiator_mock.h"
#include "wifi_direct_p2p_adapter_mock.h"
#include "softbus_errcode.h"
#include "resource_manager.h"
#include "negotiate_message.h"
#include "softbus_conn_manager.h"
#include "softbus_feature_config.h"
#include "wifi_direct_timer_list.h"
#include "wifi_direct_work_queue.h"
#include "wifi_direct_ipv4_info.h"
#include "inner_link.h"

#define WIFI_CFG_INFO_MAX_LEN 512

using namespace testing::ext;
using testing::Return;
namespace OHOS {
class WifiProcessorV1MockTest : public testing::Test {
public:
    WifiProcessorV1MockTest()
    {}
    ~WifiProcessorV1MockTest()
    {}
    static void SetUpTestV1CaseForMock() {}
    static void TearDownTestV1CaseForMock() {}
    void SetUp() override {}
    void TearDown() override {}
};

void SetUpTestV1CaseForMock(void)
{
    SoftbusConfigInit();
    ConnServerInit();
}

/*
* @tc.name: testV1CreateLink001
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1CreateLink001, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();

    struct WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(connectInfo), 0, sizeof(connectInfo));
    connectInfo.requestId = 1;
    connectInfo.pid = 1;
    connectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    connectInfo.expectApiRole = WIFI_DIRECT_API_ROLE_GO;
    const char str[] = "00:1A:2B:3C:4D:56";
    strcpy_s(connectInfo.remoteMac, sizeof(connectInfo.remoteMac), str);
    connectInfo.isNetworkDelegate = true;
    connectInfo.linkId = 4;
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 11111111);
    connectInfo.negoChannel = (struct WifiDirectNegotiateChannel *)&channel;

    DefaultNegotiateChannelMock defaultMock;
    EXPECT_CALL(defaultMock, AuthGetDeviceUuid).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetSelfWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetStationFrequency).WillRepeatedly(Return(5254));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWideBandSupported).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiConnected).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiApEnabled).WillRepeatedly(Return(false));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));

    ResourceManagerInit();

    int32_t ret = self->createLink(&connectInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DefaultNegotiateChannelDestructor(&channel);
}

/*
* @tc.name: testV1CreateLink002
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1CreateLink002, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();

    struct WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(connectInfo), 0, sizeof(connectInfo));
    connectInfo.requestId = 2;
    connectInfo.pid = 2;
    connectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    connectInfo.expectApiRole = WIFI_DIRECT_API_ROLE_GO;
    const char str[] = "00:1A:2B:3C:4D:56";
    strcpy_s(connectInfo.remoteMac, sizeof(connectInfo.remoteMac), str);
    connectInfo.isNetworkDelegate = true;
    connectInfo.linkId = 4;
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 11111111);
    connectInfo.negoChannel = (struct WifiDirectNegotiateChannel *)&channel;

    DefaultNegotiateChannelMock defaultMock;
    EXPECT_CALL(defaultMock, AuthGetDeviceUuid).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiDirectP2pAdapterMock, RequestGcIp).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetSelfWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetStationFrequency).WillRepeatedly(Return(5254));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWideBandSupported).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiConnected).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiApEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkReuse).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));

    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    WifiDirectTimerListInit();
    WifiDirectWorkQueueInit();
    struct WifiDirectIpv4Info ipv4;
    WifiDirectIpStringToIpv4("192.168.1.1", &ipv4);
    info->putRawData(info, II_KEY_IPV4, &ipv4, sizeof(ipv4));

    int32_t ret = self->createLink(&connectInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DefaultNegotiateChannelDestructor(&channel);
}

/*
* @tc.name: testV1CreateLink003
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1CreateLink003, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();

    struct WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(connectInfo), 0, sizeof(connectInfo));
    connectInfo.requestId = 3;
    connectInfo.pid = 3;
    connectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    connectInfo.expectApiRole = WIFI_DIRECT_API_ROLE_GC;
    const char str[] = "00:1A:2B:3C:4D:56";
    strcpy_s(connectInfo.remoteMac, sizeof(connectInfo.remoteMac), str);
    connectInfo.isNetworkDelegate = true;
    connectInfo.linkId = 4;
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 11111111);
    connectInfo.negoChannel = (struct WifiDirectNegotiateChannel *)&channel;

    DefaultNegotiateChannelMock defaultMock;
    EXPECT_CALL(defaultMock, AuthGetDeviceUuid).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetSelfWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetStationFrequency).WillRepeatedly(Return(5254));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWideBandSupported).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiConnected).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiApEnabled).WillRepeatedly(Return(false));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));

    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GC);

    int32_t ret = self->createLink(&connectInfo);
    EXPECT_EQ(ret, V1_ERROR_GC_CONNECTED_TO_ANOTHER_DEVICE);
    DefaultNegotiateChannelDestructor(&channel);
}

/*
* @tc.name: testDisconnectLink001
* @tc.desc: test DisconnectLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1DisconnectLink001, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();

    struct WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(connectInfo), 0, sizeof(connectInfo));
    connectInfo.requestId = 4;
    connectInfo.pid = 4;
    connectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    connectInfo.expectApiRole = WIFI_DIRECT_ROLE_GO;
    char myMac[MAC_ADDR_STR_LEN] = "00:11:22:33:44:55";
    strcpy_s(connectInfo.remoteMac, sizeof(connectInfo.remoteMac), myMac);
    connectInfo.isNetworkDelegate = true;
    connectInfo.linkId = 4;
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 11111111);
    connectInfo.negoChannel = (struct WifiDirectNegotiateChannel *)&channel;
    struct InnerLink innerlink;
    (void)memset_s(&innerlink, sizeof(innerlink), 0, sizeof(innerlink));
    InnerLinkConstructor(&innerlink);
    innerlink.putString(&innerlink, IL_KEY_REMOTE_BASE_MAC, "00:1A:2B:3C:4D:56");

    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, PostData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleSuccess).WillRepeatedly(Return());
    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));

    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);

    int32_t ret = self->disconnectLink(&connectInfo, &innerlink);
    EXPECT_EQ(ret, SOFTBUS_OK);
    InnerLinkDestructor(&innerlink);
    DefaultNegotiateChannelDestructor(&channel);
}

/*
* @tc.name: testDisconnectLink002
* @tc.desc: test DisconnectLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1DisconnectLink002, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();

    struct WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(connectInfo), 0, sizeof(connectInfo));
    connectInfo.requestId = 5;
    connectInfo.pid = 5;
    connectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    connectInfo.expectApiRole = WIFI_DIRECT_ROLE_GO;
    char myMac[MAC_ADDR_STR_LEN] = "00:11:22:33:44:55";
    strcpy_s(connectInfo.remoteMac, sizeof(connectInfo.remoteMac), myMac);
    connectInfo.isNetworkDelegate = true;
    connectInfo.linkId = 4;
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 11111111);
    connectInfo.negoChannel = (struct WifiDirectNegotiateChannel *)&channel;
    struct InnerLink innerlink;
    (void)memset_s(&innerlink, sizeof(innerlink), 0, sizeof(innerlink));
    InnerLinkConstructor(&innerlink);
    innerlink.putString(&innerlink, IL_KEY_REMOTE_BASE_MAC, "00:1A:2B:3C:4D:56");

    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, PostData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleSuccess).WillRepeatedly(Return());
    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));

    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 3);

    int32_t ret = self->disconnectLink(&connectInfo, &innerlink);
    EXPECT_EQ(ret, SOFTBUS_OK);
    InnerLinkDestructor(&innerlink);
    DefaultNegotiateChannelDestructor(&channel);
}

/*
* @tc.name: testDisconnectLink003
* @tc.desc: test DisconnectLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1DisconnectLink003, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();

    struct WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(connectInfo), 0, sizeof(connectInfo));
    connectInfo.requestId = 6;
    connectInfo.pid = 6;
    connectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    connectInfo.expectApiRole = WIFI_DIRECT_ROLE_GO;
    char myMac[MAC_ADDR_STR_LEN] = "00:11:22:33:44:55";
    strcpy_s(connectInfo.remoteMac, sizeof(connectInfo.remoteMac), myMac);
    connectInfo.isNetworkDelegate = true;
    connectInfo.linkId = 4;
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 11111111);
    connectInfo.negoChannel = (struct WifiDirectNegotiateChannel *)&channel;
    struct InnerLink innerlink;
    (void)memset_s(&innerlink, sizeof(innerlink), 0, sizeof(innerlink));
    InnerLinkConstructor(&innerlink);
    innerlink.putString(&innerlink, IL_KEY_REMOTE_BASE_MAC, "00:1A:2B:3C:4D:56");

    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, PostData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleSuccess).WillRepeatedly(Return());
    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));
    
    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 1);

    int32_t ret = self->disconnectLink(&connectInfo, &innerlink);
    EXPECT_EQ(ret, SOFTBUS_OK);
    InnerLinkDestructor(&innerlink);
    DefaultNegotiateChannelDestructor(&channel);
}

/*
* @tc.name: testReuseLink001
* @tc.desc: test ReuseLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1ReuseLink001, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();

    struct WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(connectInfo), 0, sizeof(connectInfo));
    connectInfo.requestId = 7;
    connectInfo.pid = 7;
    connectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    connectInfo.expectApiRole = WIFI_DIRECT_ROLE_GO;
    char myMac[MAC_ADDR_STR_LEN] = "00:11:22:33:44:55";
    strcpy_s(connectInfo.remoteMac, sizeof(connectInfo.remoteMac), myMac);
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 11111111);
    connectInfo.negoChannel = (struct WifiDirectNegotiateChannel *)&channel;
    struct InnerLink innerlink;
    (void)memset_s(&innerlink, sizeof(innerlink), 0, sizeof(innerlink));
    InnerLinkConstructor(&innerlink);
    innerlink.putString(&innerlink, IL_KEY_REMOTE_BASE_MAC, "00:1A:2B:3C:4D:56");
    struct WifiDirectIpv4Info ipv4;
    WifiDirectIpStringToIpv4("192.168.1.1", &ipv4);
    innerlink.putRawData(&innerlink, IL_KEY_REMOTE_IPV4, &ipv4, sizeof(ipv4));

    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(true));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));

    ResourceManagerInit();
   
    int32_t ret = self->reuseLink(&connectInfo, &innerlink);
    InnerLinkDestructor(&innerlink);
    DefaultNegotiateChannelDestructor(&channel);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testProcessNegotiateMessage001
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1ProcessNegotiateMessage001, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_SELF_WIFI_CONFIG, "ssss");
    msg->putInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GO_INFO);
    msg->putString(msg, NM_KEY_GO_MAC, "00:11:22:33:44:55");
    msg->putString(msg, NM_KEY_GC_MAC, "11:22:33:44:55:66");
    msg->putInt(msg, NM_KEY_EXPECTED_ROLE,  WIFI_DIRECT_API_ROLE_GO);
    msg->putInt(msg, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    msg->putInt(msg, NM_KEY_ROLE, WIFI_DIRECT_API_ROLE_GC);

    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, SetPeerWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    
    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 1);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");
    

    int32_t ret = self->processNegotiateMessage(CMD_CONN_V1_REQ, msg);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testProcessNegotiateMessage002
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1ProcessNegotiateMessage002, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_SELF_WIFI_CONFIG, "ssss");
    msg->putInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GO_INFO);
    msg->putString(msg, NM_KEY_GO_MAC, "00:11:22:33:44:55");
    msg->putString(msg, NM_KEY_GC_MAC, "11:22:33:44:55:66");
    msg->putInt(msg, NM_KEY_EXPECTED_ROLE,  WIFI_DIRECT_API_ROLE_GO);
    msg->putInt(msg, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    msg->putInt(msg, NM_KEY_ROLE, WIFI_DIRECT_ROLE_NONE);

    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, SetPeerWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    
    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 1);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");
    

    int32_t ret = self->processNegotiateMessage(CMD_CONN_V1_REQ, msg);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testProcessNegotiateMessage003
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1ProcessNegotiateMessage003, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_SELF_WIFI_CONFIG, "ssss");
    msg->putInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GC_INFO);
    msg->putString(msg, NM_KEY_GO_MAC, "00:11:22:33:44:55");
    msg->putString(msg, NM_KEY_GC_MAC, "11:22:33:44:55:66");
    msg->putInt(msg, NM_KEY_EXPECTED_ROLE,  WIFI_DIRECT_API_ROLE_GO);
    msg->putInt(msg, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    msg->putInt(msg, NM_KEY_ROLE, WIFI_DIRECT_ROLE_NONE);
    msg->putInt(msg, NM_KEY_SESSION_ID, 8);
    msg->putBoolean(msg, NM_KEY_WIDE_BAND_SUPPORTED, true);
    msg->putInt(msg, NM_KEY_STATION_FREQUENCY, 5254);
    msg->putString(msg, NM_KEY_GC_CHANNEL_LIST, "");

    DefaultNegotiateChannelMock defaultMock;
    EXPECT_CALL(defaultMock, AuthGetDeviceUuid).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, SetPeerWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetStationFrequency).WillRepeatedly(Return(5254));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWideBandSupported).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetSelfWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, RequestGcIp).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkReuse).WillRepeatedly(Return(SOFTBUS_ERR));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    
    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 1);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");
    

    int32_t ret = self->processNegotiateMessage(CMD_CONN_V1_REQ, msg);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testProcessNegotiateMessage004
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1ProcessNegotiateMessage004, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_SELF_WIFI_CONFIG, "ssss");
    msg->putInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_RESULT);
    msg->putString(msg, NM_KEY_GO_MAC, "00:11:22:33:44:55");
    msg->putString(msg, NM_KEY_GC_MAC, "11:22:33:44:55:66");
    msg->putInt(msg, NM_KEY_EXPECTED_ROLE,  WIFI_DIRECT_API_ROLE_GO);
    msg->putInt(msg, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    msg->putInt(msg, NM_KEY_ROLE, WIFI_DIRECT_ROLE_NONE);
    msg->putInt(msg, NM_KEY_SESSION_ID, 9);
    msg->putString(msg, NM_KEY_GC_IP, "192.168.0.2");
    msg->putString(msg, NM_KEY_IP, "192.168.0.3");
    msg->putString(msg, NM_KEY_MAC, "1B:22:33:44:55:66");
    msg->putString(msg, NM_KEY_GROUP_CONFIG, "11:22:33:44:55:66");

    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, SetPeerWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    
    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");
    info->putInt(info, II_KEY_REUSE_COUNT, 0);

    int32_t ret = self->processNegotiateMessage(CMD_CONN_V1_REQ, msg);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testProcessNegotiateMessage005
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1ProcessNegotiateMessage005, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_SELF_WIFI_CONFIG, "ssss");
    msg->putInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_RESULT);
    msg->putString(msg, NM_KEY_GO_MAC, "00:11:22:33:44:55");
    msg->putString(msg, NM_KEY_GC_MAC, "11:22:33:44:55:66");
    msg->putInt(msg, NM_KEY_EXPECTED_ROLE,  WIFI_DIRECT_API_ROLE_GO);
    msg->putInt(msg, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    msg->putInt(msg, NM_KEY_ROLE, WIFI_DIRECT_ROLE_NONE);
    msg->putInt(msg, NM_KEY_SESSION_ID, 9);
    msg->putString(msg, NM_KEY_GC_IP, "192.168.0.2");
    msg->putString(msg, NM_KEY_IP, "192.168.0.3");
    msg->putString(msg, NM_KEY_MAC, "1B:22:33:44:55:66");
    msg->putString(msg, NM_KEY_GROUP_CONFIG, "11:22:33:44:55:66");

    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, SetPeerWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, RequestGcIp).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    
    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 0);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");
    

    int32_t ret = self->processNegotiateMessage(CMD_CONN_V1_RESP, msg);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, V1_ERROR_CONNECTED_WITH_MISMATCHED_ROLE);
}

/*
* @tc.name: testProcessNegotiateMessage006
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1ProcessNegotiateMessage006, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_SELF_WIFI_CONFIG, "ssss");
    msg->putInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GC_INFO);
    msg->putString(msg, NM_KEY_GO_MAC, "00:11:22:33:44:55");
    msg->putString(msg, NM_KEY_GC_MAC, "11:22:33:44:55:66");
    msg->putInt(msg, NM_KEY_EXPECTED_ROLE,  WIFI_DIRECT_API_ROLE_GO);
    msg->putInt(msg, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    msg->putInt(msg, NM_KEY_ROLE, WIFI_DIRECT_ROLE_NONE);
    msg->putInt(msg, NM_KEY_SESSION_ID, 9);
    msg->putString(msg, NM_KEY_GC_IP, "192.168.0.2");
    msg->putString(msg, NM_KEY_IP, "192.168.0.3");
    msg->putString(msg, NM_KEY_MAC, "1B:22:33:44:55:66");
    msg->putString(msg, NM_KEY_GROUP_CONFIG, "11:22:33:44:55:66");

    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, SetPeerWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    
    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 1);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");

    int32_t ret = self->processNegotiateMessage(CMD_CONN_V1_RESP, msg);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, ERROR_WIFI_DIRECT_WRONG_NEGOTIATION_MSG);
}

/*
* @tc.name: testProcessNegotiateMessage007
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1ProcessNegotiateMessage007, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_SELF_WIFI_CONFIG, "ssss");
    msg->putInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GC_INFO);
    msg->putString(msg, NM_KEY_GO_MAC, "00:11:22:33:44:55");
    msg->putString(msg, NM_KEY_GC_MAC, "11:22:33:44:55:66");
    msg->putInt(msg, NM_KEY_EXPECTED_ROLE,  WIFI_DIRECT_API_ROLE_GO);
    msg->putInt(msg, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    msg->putInt(msg, NM_KEY_ROLE, WIFI_DIRECT_ROLE_NONE);
    msg->putInt(msg, NM_KEY_SESSION_ID, 9);
    msg->putString(msg, NM_KEY_GC_IP, "192.168.0.2");
    msg->putString(msg, NM_KEY_IP, "192.168.0.3");
    msg->putString(msg, NM_KEY_MAC, "1B:22:33:44:55:66");
    msg->putString(msg, NM_KEY_GROUP_CONFIG, "11:22:33:44:55:66");

    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, SetPeerWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleSuccess).WillRepeatedly(Return());
    
    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 0);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");

    int32_t ret = self->processNegotiateMessage(CMD_DISCONNECT_V1_REQ, msg);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testProcessNegotiateMessage008
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1ProcessNegotiateMessage008, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_SELF_WIFI_CONFIG, "ssss");
    msg->putInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GC_INFO);
    msg->putString(msg, NM_KEY_GO_MAC, "00:11:22:33:44:55");
    msg->putString(msg, NM_KEY_GC_MAC, "11:22:33:44:55:66");
    msg->putInt(msg, NM_KEY_EXPECTED_ROLE,  WIFI_DIRECT_API_ROLE_GO);
    msg->putInt(msg, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    msg->putInt(msg, NM_KEY_ROLE, WIFI_DIRECT_ROLE_NONE);
    msg->putInt(msg, NM_KEY_SESSION_ID, 9);
    msg->putString(msg, NM_KEY_GC_IP, "192.168.0.2");
    msg->putString(msg, NM_KEY_IP, "192.168.0.3");
    msg->putString(msg, NM_KEY_MAC, "1B:22:33:44:55:66");
    msg->putString(msg, NM_KEY_GROUP_CONFIG, "11:22:33:44:55:66");

    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, SetPeerWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleSuccess).WillRepeatedly(Return());
    
    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 0);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");

    int32_t ret = self->processNegotiateMessage(CMD_DISCONNECT_V1_REQ, msg);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testProcessNegotiateMessage009
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1ProcessNegotiateMessage009, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_SELF_WIFI_CONFIG, "ssss");
    msg->putInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GC_INFO);
    msg->putString(msg, NM_KEY_GO_MAC, "00:11:22:33:44:55");
    msg->putString(msg, NM_KEY_GC_MAC, "11:22:33:44:55:66");
    msg->putInt(msg, NM_KEY_EXPECTED_ROLE,  WIFI_DIRECT_API_ROLE_GO);
    msg->putInt(msg, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    msg->putInt(msg, NM_KEY_ROLE, WIFI_DIRECT_ROLE_NONE);
    msg->putInt(msg, NM_KEY_SESSION_ID, 9);
    msg->putString(msg, NM_KEY_GC_IP, "192.168.0.2");
    msg->putString(msg, NM_KEY_IP, "192.168.0.3");
    msg->putString(msg, NM_KEY_MAC, "1B:22:33:44:55:66");
    msg->putString(msg, NM_KEY_GROUP_CONFIG, "11:22:33:44:55:66");

    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, SetPeerWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleSuccess).WillRepeatedly(Return());
    
    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 0);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");

    int32_t ret = self->processNegotiateMessage(CMD_REUSE_REQ, msg);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testProcessNegotiateMessage0010
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1ProcessNegotiateMessage0010, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_SELF_WIFI_CONFIG, "ssss");
    msg->putInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GC_INFO);
    msg->putString(msg, NM_KEY_GO_MAC, "00:11:22:33:44:55");
    msg->putString(msg, NM_KEY_GC_MAC, "11:22:33:44:55:66");
    msg->putInt(msg, NM_KEY_EXPECTED_ROLE,  WIFI_DIRECT_API_ROLE_GO);
    msg->putInt(msg, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    msg->putInt(msg, NM_KEY_ROLE, WIFI_DIRECT_ROLE_NONE);
    msg->putInt(msg, NM_KEY_SESSION_ID, 9);
    msg->putInt(msg, NM_KEY_RESULT, SOFTBUS_OK);
    msg->putString(msg, NM_KEY_GC_IP, "192.168.0.2");
    msg->putString(msg, NM_KEY_IP, "192.168.0.3");
    msg->putString(msg, NM_KEY_MAC, "1B:22:33:44:55:66");
    msg->putString(msg, NM_KEY_GROUP_CONFIG, "11:22:33:44:55:66");

    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, SetPeerWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkReuse).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleSuccess).WillRepeatedly(Return());
    EXPECT_CALL(wifiDirectNegotiatorMock, PostData).WillRepeatedly(Return(SOFTBUS_OK));
    
    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 2);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");
    struct InnerLink innerlink;
    (void)memset_s(&innerlink, sizeof(innerlink), 0, sizeof(innerlink));
    InnerLinkConstructorWithArgs(&innerlink, WIFI_DIRECT_CONNECT_TYPE_P2P, true, "P2P0", "00:11:2B:33:44:55");
    innerlink.putString(&innerlink, IL_KEY_REMOTE_BASE_MAC, "00:1A:2B:3C:4D:56");

    int32_t ret = self->processNegotiateMessage(CMD_REUSE_RESP, msg);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: testProcessNegotiateMessage0011
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1ProcessNegotiateMessage0011, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    self->pendingRequestMsg = NULL;
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_SELF_WIFI_CONFIG, "ssss");
    msg->putInt(msg, NM_KEY_CONTENT_TYPE, P2P_CONTENT_TYPE_GC_INFO);
    msg->putString(msg, NM_KEY_GO_MAC, "00:11:22:33:44:55");
    msg->putString(msg, NM_KEY_GC_MAC, "11:22:33:44:55:66");
    msg->putInt(msg, NM_KEY_EXPECTED_ROLE,  WIFI_DIRECT_API_ROLE_GO);
    msg->putInt(msg, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    msg->putInt(msg, NM_KEY_ROLE, WIFI_DIRECT_ROLE_NONE);
    msg->putInt(msg, NM_KEY_SESSION_ID, 9);
    msg->putString(msg, NM_KEY_GC_IP, "192.168.0.2");
    msg->putString(msg, NM_KEY_IP, "192.168.0.3");
    msg->putString(msg, NM_KEY_MAC, "1B:22:33:44:55:66");
    msg->putString(msg, NM_KEY_GROUP_CONFIG, "11:22:33:44:55:66");
    msg->putString(msg, NM_KEY_INTERFACE_NAME, "p2p0");

    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, SetPeerWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiDirectP2pAdapterMock, P2pShareLinkRemoveGroup).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleSuccess).WillRepeatedly(Return());
    EXPECT_CALL(wifiDirectNegotiatorMock, PostData).WillRepeatedly(Return(SOFTBUS_OK));
    
    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 0);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");

    int32_t ret = self->processNegotiateMessage(CMD_PC_GET_INTERFACE_INFO_REQ, msg);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testOnOperationEvent001
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1OnOperationEvent001, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = 10;
    constexpr int32_t requestId = 10;
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    self->currentMsg = msg;
    self->needReply =  true;
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = self->onOperationEvent(requestId, result);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testOnOperationEvent002
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1OnOperationEvent002, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = 11;
    constexpr int32_t requestId = 11;
    self->currentMsg = nullptr;
    self->needReply =  true;

    int32_t ret = self->onOperationEvent(requestId, result);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testOnOperationEvent003
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1OnOperationEvent003, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = OK;
    constexpr int32_t requestId = 12;
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_MAC, "1B:22:33:44:55:66");
    self->currentMsg = msg;
    self->needReply =  true;
    self->currentState = PROCESSOR_STATE_WAITING_CREATE_GROUP;
    self->currentRequestId = 12;

    DefaultNegotiateChannelMock defaultMock;
    EXPECT_CALL(defaultMock, AuthGetDeviceUuid).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, RequestGcIp).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetSelfWifiConfigInfo).WillRepeatedly(Return(SOFTBUS_OK));

    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 1);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");
    struct WifiDirectIpv4Info ipv4;
    WifiDirectIpStringToIpv4("192.168.1.1", &ipv4);
    info->putRawData(info, II_KEY_IPV4, &ipv4, sizeof(ipv4));

    int32_t ret = self->onOperationEvent(requestId, result);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testOnOperationEvent004
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1OnOperationEvent004, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = OK;
    constexpr int32_t requestId = 12;
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_MAC, "1B:22:33:44:55:66");
    self->currentMsg = msg;
    self->needReply =  false;
    self->currentState = PROCESSOR_STATE_WAITING_CREATE_GROUP;
    self->currentRequestId = 12;

    DefaultNegotiateChannelMock defaultMock;
    EXPECT_CALL(defaultMock, AuthGetDeviceUuid).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, RequestGcIp).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(true));

    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 1);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");
    struct WifiDirectIpv4Info ipv4;
    WifiDirectIpStringToIpv4("192.168.1.1", &ipv4);
    info->putRawData(info, II_KEY_IPV4, &ipv4, sizeof(ipv4));

    int32_t ret = self->onOperationEvent(requestId, result);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testOnOperationEvent005
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1OnOperationEvent005, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = OK;
    constexpr int32_t requestId = 13;
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putString(msg, NM_KEY_MAC, "1B:22:33:44:55:66");
    msg->putString(msg, NM_KEY_GROUP_CONFIG, "11:22:33:44:55:66");
    msg->putString(msg, NM_KEY_GO_IP, "192.168.1.4");
    self->currentMsg = msg;
    self->needReply =  false;
    self->currentState = PROCESSOR_STATE_WAITING_CONNECT_GROUP;
    self->currentRequestId = 12;

    DefaultNegotiateChannelMock defaultMock;
    EXPECT_CALL(defaultMock, AuthGetDeviceUuid).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    EXPECT_CALL(wifiDirectP2pAdapterMock, RequestGcIp).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(true));

    ResourceManagerInit();
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    info->putInt(info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    info->putInt(info, II_KEY_REUSE_COUNT, 1);
    info->putString(info, II_KEY_BASE_MAC, "00:11:22:33:44:55");
    struct WifiDirectIpv4Info ipv4;
    WifiDirectIpStringToIpv4("192.168.1.1", &ipv4);
    info->putRawData(info, II_KEY_IPV4, &ipv4, sizeof(ipv4));

    int32_t ret = self->onOperationEvent(requestId, result);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: testOnOperationEvent006
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1OnOperationEvent006, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = OK;
    constexpr int32_t requestId = 14;
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    self->currentMsg = msg;
    self->needReply =  false;
    self->currentState = PROCESSOR_STATE_WAITING_REMOVE_GROUP;
    self->currentRequestId = 12;

    WifiDirectNegotiatorMock wifiDirectNegotiatorMock;
    EXPECT_CALL(wifiDirectNegotiatorMock, HandleSuccess).WillRepeatedly(Return());

    int32_t ret = self->onOperationEvent(requestId, result);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testOnOperationEvent007
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV1MockTest, testV1OnOperationEvent007, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = OK;
    constexpr int32_t requestId = 14;
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    self->currentMsg = msg;
    self->needReply =  false;
    self->currentState = PROCESSOR_STATE_WAITING_DISCONNECTED_NO_DESTROY;
    self->currentRequestId = 12;

    int32_t ret = self->onOperationEvent(requestId, result);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

}