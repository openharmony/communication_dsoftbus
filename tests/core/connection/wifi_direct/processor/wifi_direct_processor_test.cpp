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
#include "p2p_v2_processor.h"
#include "link_manager.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "negotiate_message.h"
#include "wifi_direct_processor_factory.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "channel/default_negotiate_channel.h"
#include "wifi_direct_processor_mock.h"
#include "resource_manager.h"
#include "wifi_direct_ipv4_info.h"
#include "link_info.h"
#include "wifi_direct_decision_center.h"
#include "wifi_direct_manager.h"
#include "wifi_direct_negotiator.h"

using namespace testing::ext;
using testing::Return;
namespace OHOS {
class WifiProcessorTest : public testing::Test {
public:
    WifiProcessorTest()
    {}
    ~WifiProcessorTest()
    {}
    static void SetUpTestCase();
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

void WifiProcessorTest::SetUpTestCase()
{
    SoftbusConfigInit();
    ConnServerInit();
}

/*
* @tc.name: testFactoryCreateProcessor001
* @tc.desc: test FactoryCreateProcessor
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testFactoryCreateProcessor001, TestSize.Level1)
{
    struct WifiDirectProcessor *wifiProcessor =
        GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1);
    ASSERT_STREQ(wifiProcessor->name, "P2pV1Processor");

    struct WifiDirectProcessor *wifiProcessor1 =
        GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V2);
    ASSERT_STREQ(wifiProcessor1->name, "P2pV2Processor");

    struct WifiDirectProcessor *wifiProcessor2 =
        GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_HML);
    if (!wifiProcessor2) {
        int ret = 0;
        EXPECT_EQ(ret, 0);
    }
}

/*
* @tc.name: testDisconnectLink001
* @tc.desc: test DisconnectLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1DisconnectLink001, TestSize.Level1)
{
    struct WifiDirectConnectInfo connectInfo;
    WifiProcessorMock wifiProcessorMock;
    (void)memset_s(&connectInfo, sizeof(connectInfo), 0, sizeof(connectInfo));
    connectInfo.requestId = 2;
    connectInfo.pid = 3;
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
    EXPECT_EQ(GetP2pV1Processor()->disconnectLink(nullptr, &innerlink), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetP2pV1Processor()->disconnectLink(&connectInfo, nullptr), SOFTBUS_INVALID_PARAM);
    const char *interface = "1";
    struct InterfaceInfo interfaceInfo;
    InterfaceInfoConstructor(&interfaceInfo);
    interfaceInfo.putInt(&interfaceInfo, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    EXPECT_CALL(wifiProcessorMock, GetInterfaceInfo(interface)).WillRepeatedly(Return(&interfaceInfo));
    int32_t ret = GetP2pV1Processor()->disconnectLink(&connectInfo, &innerlink);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: testProcessNegotiateMessage001
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1ProcessNegotiateMessage001, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 11111);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)(struct WifiDirectNegotiateChannel *)&channel);

    int32_t ret = self->processNegotiateMessage(CMD_CONN_V1_REQ, msg);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: testProcessNegotiateMessage002
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1ProcessNegotiateMessage002, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();

    int32_t ret = self->processNegotiateMessage(CMD_CONN_V1_RESP, msg);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: testProcessNegotiateMessage003
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1ProcessNegotiateMessage003, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    int32_t ret = self->processNegotiateMessage(CMD_DISCONNECT_V1_REQ, msg);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: testProcessNegotiateMessage004
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1ProcessNegotiateMessage004, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
   
    int32_t ret = self->processNegotiateMessage(CMD_REUSE_RESP, msg);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, V1_ERROR_CONNECTED_WITH_MISMATCHED_ROLE);
}

/*
* @tc.name: testProcessNegotiateMessage005
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1ProcessNegotiateMessage005, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    int32_t ret = self->processNegotiateMessage(CMD_PC_GET_INTERFACE_INFO_REQ, msg);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: testProcessNegotiateMessage006
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1ProcessNegotiateMessage006, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();

    int32_t ret = self->processNegotiateMessage(CMD_PC_GET_INTERFACE_INFO_RESP, msg);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: testOnOperationEvent001
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1OnOperationEvent001, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    int32_t result = 1;
    int32_t requestId = 1;
    struct NegotiateMessage msg;
    NegotiateMessageConstructor(&msg);
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 11111);
    msg.putPointer(&msg, NM_KEY_NEGO_CHANNEL, (void **)(struct WifiDirectNegotiateChannel *)&channel);
    int32_t ret = self->onOperationEvent(requestId, result);
    DefaultNegotiateChannelDestructor(&channel);
    NegotiateMessageDestructor(&msg);
    EXPECT_TRUE(ret == false);
}

/*
* @tc.name: testOnOperationEvent002
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1OnOperationEvent002, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = 1;
    constexpr int32_t requestId = 1;
    int32_t ret = self->onOperationEvent(requestId, result);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: testOnOperationEvent003
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1OnOperationEvent003, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = OK;
    constexpr int32_t requestId = 1;
    self->currentState = PROCESSOR_STATE_WAITING_CREATE_GROUP;
    int32_t ret = self->onOperationEvent(requestId, result);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: testOnOperationEvent004
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1OnOperationEvent004, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = OK;
    constexpr int32_t requestId = 1;
    self->currentState = PROCESSOR_STATE_WAITING_CONNECT_GROUP;
    int32_t ret = self->onOperationEvent(requestId, result);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: testOnOperationEvent005
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1OnOperationEvent005, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = OK;
    constexpr int32_t requestId = 1;
    self->currentState = PROCESSOR_STATE_WAITING_REMOVE_GROUP;
    int32_t ret = self->onOperationEvent(requestId, result);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testOnOperationEvent006
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1OnOperationEvent006, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = OK;
    constexpr int32_t requestId = 1;
    self->currentState = PROCESSOR_STATE_WAITING_SERVER_DISTROYED;
    int32_t ret = self->onOperationEvent(requestId, result);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
 * @tc.name: testProcessUnhandledRequest001
 * @tc.desc: test ProcessUnhandledRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiProcessorTest, testV1ProcessUnhandledRequest001, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t reason = 100;
    struct NegotiateMessage msg;
    NegotiateMessageConstructor(&msg);
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 11111);
    msg.putPointer(&msg, NM_KEY_NEGO_CHANNEL, (void **)(struct WifiDirectNegotiateChannel *)&channel);
    msg.putInt(&msg, NM_KEY_COMMAND_TYPE, CMD_REUSE_REQ);

    self->processUnhandledRequest(&msg, reason);
    DefaultNegotiateChannelDestructor(&channel);
    NegotiateMessageDestructor(&msg);
}

/*
* @tc.name: testReuseLink001
* @tc.desc: test ReuseLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1ReuseLink001, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct WifiDirectConnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = 1111;
    char myMac[MAC_ADDR_STR_LEN] = "00:11:22:33:44:55";
    strcpy_s(info.remoteMac, sizeof(info.remoteMac), myMac);
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 222);
    info.negoChannel = (struct WifiDirectNegotiateChannel*)&channel;

    struct InnerLink link;
    InnerLinkConstructor(&link);
    ResourceManagerInit();
    struct InterfaceInfo *info1 = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    struct WifiDirectIpv4Info *localIpv4 = (struct WifiDirectIpv4Info *)info1->get(info1, II_KEY_IPV4, NULL, NULL);
    link.putRawData(&link, IL_KEY_LOCAL_IPV4, localIpv4, sizeof(struct WifiDirectIpv4Info));
    int32_t ret = self->reuseLink(&info, &link);
    InnerLinkDestructor(&link);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: testV1CreateLink001
* @tc.desc: test CreateLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1CreateLink001, TestSize.Level1)
{
    WifiProcessorMock wifiProcessorMock;
    struct WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(connectInfo), 0, sizeof(connectInfo));
    EXPECT_EQ(GetP2pV1Processor()->createLink(nullptr), SOFTBUS_INVALID_PARAM);

    connectInfo.requestId = 2;
    connectInfo.pid = 3;
    connectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    connectInfo.expectApiRole = WIFI_DIRECT_ROLE_GO;
    const char str[] = "00:1A:2B:3C:4D:56";
    strcpy_s(connectInfo.remoteMac, sizeof(32), str);
    connectInfo.isNetworkDelegate = true;
    connectInfo.linkId = 4;
    struct WifiProcessorMock::WifiDirectNegoChannelMock channel;
    wifiProcessorMock.WifiDirectNegoChannelMockConstructor(&channel, 11111111);
    
    connectInfo.negoChannel = (struct WifiDirectNegotiateChannel *)&channel;

    wifiProcessorMock.SetupSuccessStub();
    EXPECT_EQ(GetP2pV1Processor()->createLink(&connectInfo), V1_ERROR_IF_NOT_AVAILABLE);

    struct InterfaceInfo interfaceInfo;
    InterfaceInfoConstructor(&interfaceInfo);
    interfaceInfo.putInt(&interfaceInfo, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    EXPECT_EQ(GetP2pV1Processor()->createLink(&connectInfo), V1_ERROR_IF_NOT_AVAILABLE);

    ResourceManagerInit();
    int32_t ret = GetP2pV1Processor()->createLink(&connectInfo);
    EXPECT_EQ(ret, V1_ERROR_IF_NOT_AVAILABLE);
}

/*
* @tc.name: testV2ProcessReuseLink001
* @tc.desc: test V2ProcessReuseLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV2ProcessReuseLink001, TestSize.Level1)
{
    struct P2pV2Processor *self = GetP2pV2Processor();
    struct WifiDirectConnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = 1111;
    char myMac[MAC_ADDR_STR_LEN] = "00:11:22:33:44:55";
    strcpy_s(info.remoteMac, sizeof(info.remoteMac), myMac);
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 222);
    info.negoChannel = (struct WifiDirectNegotiateChannel*)&channel;

    struct InnerLink link;
    InnerLinkConstructor(&link);
    ResourceManagerInit();
    link.putString(&link, IL_KEY_LOCAL_INTERFACE, "IF_NAME_P2P");

    int32_t ret = self->reuseLink(&info, &link);
    InnerLinkDestructor(&link);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: testV2OnOperationEvent001
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV2OnOperationEvent001, TestSize.Level1)
{
    struct P2pV2Processor *self = GetP2pV2Processor();
    self->currentRequestId = 3;
    EXPECT_EQ(GetP2pV2Processor()->onOperationEvent(2, SOFTBUS_OK), SOFTBUS_ERR);

    self->currentRequestId = 2;
    self->currentMsg = nullptr;
    EXPECT_EQ(GetP2pV2Processor()->onOperationEvent(2, SOFTBUS_OK), SOFTBUS_ERR);
  
    struct NegotiateMessage *msg = NegotiateMessageNew();
    self->currentMsg = msg;
    EXPECT_EQ(GetP2pV2Processor()->onOperationEvent(2, SOFTBUS_ERR), SOFTBUS_ERR);

    self->currentState = PROCESSOR_STATE_WAITING_CREATE_GROUP;
    LinkInfo *linkInfo = LinkInfoNew();
    linkInfo->putString(linkInfo, LI_KEY_LOCAL_INTERFACE, "p2p0");
    linkInfo->putString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "00:11:22:33:44:55");
    self->currentMsg = msg;
    self->needReply = true;
    ResourceManagerInit();
    self->currentState = PROCESSOR_STATE_WAITING_CONNECT_GROUP;
    EXPECT_EQ(GetP2pV2Processor()->onOperationEvent(2, SOFTBUS_OK), SOFTBUS_ERR);

    self->currentState = PROCESSOR_STATE_WAITING_REMOVE_GROUP;
    EXPECT_EQ(GetP2pV2Processor()->onOperationEvent(2, SOFTBUS_OK), SOFTBUS_OK);

    self->currentState = PROCESSOR_STATE_AVAILABLE;
    EXPECT_EQ(GetP2pV2Processor()->onOperationEvent(2, SOFTBUS_OK), SOFTBUS_ERR);

    LinkInfoDelete(linkInfo);
    NegotiateMessageDelete(msg);
}

/*
* @tc.name: testV2ProcessNegotiateMessage001
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV2ProcessNegotiateMessage001, TestSize.Level1)
{
    WifiDirectNegotiatorInit();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    GetP2pV2Processor()->needReply = false;
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_CONN_V2_REQ_1, msg), SOFTBUS_ERR);
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_CONN_V2_REQ_2, msg), SOFTBUS_ERR);
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_CONN_V2_REQ_3, msg), SOFTBUS_ERR);
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_CONN_V2_RESP_1, msg), SOFTBUS_ERR);
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_CONN_V2_RESP_2, msg), SOFTBUS_ERR);
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_CONN_V2_RESP_3, msg), SOFTBUS_ERR);
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_DISCONNECT_V2_REQ, msg), SOFTBUS_ERR);
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_DISCONNECT_V2_RESP, msg),
        ERROR_WIFI_DIRECT_WRONG_NEGOTIATION_MSG);
}

}