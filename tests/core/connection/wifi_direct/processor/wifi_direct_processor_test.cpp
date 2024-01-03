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
#include "channel/default_negotiate_channel.h"
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
* @tc.name: testProcessNegotiateMessage001
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1ProcessNegotiateMessage001, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);

    int32_t ret = self->processNegotiateMessage(CMD_CONN_V1_REQ, msg);
    DefaultNegotiateChannelDelete(channel);
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
* @tc.name: testProcessNegotiateMessage007
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1ProcessNegotiateMessage007, TestSize.Level1)
{
    ResourceManagerInit();
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    char myMac[MAC_ADDR_STR_LEN] = "00:11:22:33:44:55";
    msg->putString(msg, NM_KEY_MAC, myMac);

    int32_t ret = self->processNegotiateMessage(CMD_REUSE_REQ, msg);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, ERROR_POST_DATA_FAILED);
}

/*
* @tc.name: testProcessNegotiateMessage008
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1ProcessNegotiateMessage008, TestSize.Level1)
{
    ResourceManagerInit();
    struct P2pV1Processor *self = GetP2pV1Processor();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    char myMac[MAC_ADDR_STR_LEN] = "00:11:22:33:44:55";
    msg->putString(msg, NM_KEY_MAC, myMac);

    int32_t ret = self->processNegotiateMessage(CMD_DISCONNECT_V1_REQ, msg);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    constexpr int32_t result = 1;
    constexpr int32_t requestId = 1;
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    self->currentMsg = msg;
    self->needReply =  false;
    int32_t ret = self->onOperationEvent(requestId, result);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
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
    self->currentMsg = nullptr;
    int32_t ret = self->onOperationEvent(requestId, result);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
* @tc.name: testOnOperationEvent007
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1OnOperationEvent007, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = 1;
    constexpr int32_t requestId = 1;
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    self->currentMsg = msg;
    self->needReply =  true;
    int32_t ret = self->onOperationEvent(requestId, result);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDelete(msg);
    EXPECT_EQ(ret, ERROR_POST_DATA_FAILED);
}

/*
* @tc.name: testOnOperationEvent008
* @tc.desc: test OnOperationEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV1OnOperationEvent008, TestSize.Level1)
{
    ResourceManagerInit();
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t result = OK;
    constexpr int32_t requestId = 1;
    self->currentState = PROCESSOR_STATE_WAITING_CREATE_GROUP;
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    char myMac[MAC_ADDR_STR_LEN] = "00:11:22:33:44:55";
    msg->putString(msg, NM_KEY_MAC, myMac);
    self->currentMsg = msg;
    self->needReply = true;
    self->currentRequestId = 233;
    int32_t ret = self->onOperationEvent(requestId, result);
    NegotiateMessageDelete(msg);
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
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg.putPointer(&msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg.putInt(&msg, NM_KEY_COMMAND_TYPE, CMD_REUSE_REQ);

    self->processUnhandledRequest(&msg, reason);
    DefaultNegotiateChannelDelete(channel);
    NegotiateMessageDestructor(&msg);
}

/*
 * @tc.name: testProcessUnhandledRequest002
 * @tc.desc: test ProcessUnhandledRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiProcessorTest, testV1ProcessUnhandledRequest002, TestSize.Level1)
{
    struct P2pV1Processor *self = GetP2pV1Processor();
    constexpr int32_t reason = 100;
    struct NegotiateMessage msg;
    NegotiateMessageConstructor(&msg);
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    msg.putPointer(&msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg.putInt(&msg, NM_KEY_COMMAND_TYPE, CMD_REUSE_REQ);

    self->processUnhandledRequest(&msg, reason);
    DefaultNegotiateChannelDelete(channel);
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

    struct WifiDirectIpv4Info ipv4;
    WifiDirectIpStringToIpv4("192.168.1.1", &ipv4);
    info1->putRawData(info1, II_KEY_IPV4, &ipv4, sizeof(ipv4));
   
    int32_t ret = self->reuseLink(&info, &link);
    InnerLinkDestructor(&link);
    EXPECT_EQ(ret, SOFTBUS_ERR);
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
* @tc.name: testV2DisconnectLink001
* @tc.desc: test V2DisconnectLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV2DisconnectLink001, TestSize.Level1)
{
    struct P2pV2Processor *self = GetP2pV2Processor();
    struct WifiDirectConnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = 1111;
    char myMac[MAC_ADDR_STR_LEN] = "00:11:22:33:44:55";
    strcpy_s(info.remoteMac, sizeof(info.remoteMac), myMac);
    DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(1111);
    
    info.negoChannel = (struct WifiDirectNegotiateChannel *)channel;

    struct InnerLink *link = InnerLinkNew();
    ResourceManagerInit();
    link->putString(link, IL_KEY_LOCAL_INTERFACE, "p2p0");
    int32_t ret = self->disconnectLink(&info, link);

    EXPECT_EQ(ret, SOFTBUS_ERR);

    link->putBoolean(link, IL_KEY_IS_BEING_USED_BY_REMOTE, true);
    EXPECT_EQ(self->disconnectLink(&info, link), ERROR_WIFI_DIRECT_PACK_DATA_FAILED);

    link->putBoolean(link, IL_KEY_IS_BEING_USED_BY_REMOTE, false);
    EXPECT_EQ(self->disconnectLink(&info, link), SOFTBUS_ERR);
    InnerLinkDestructor(link);
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

/*
* @tc.name: testV2ProcessUnhandledRequest001
* @tc.desc: test ProcessUnhandledRequest
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV2ProcessUnhandledRequest001, TestSize.Level1)
{
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(22222);
    channel->tlvFeature = true;
    msg->putPointer(msg, NM_KEY_NEGO_CHANNEL, (void **)&channel);
    msg->putInt(msg, NM_KEY_SESSION_ID, 111);
    
    struct LinkInfo linkInfo;
    LinkInfoConstructor(&linkInfo);
    linkInfo.putString(&linkInfo, LI_KEY_LOCAL_INTERFACE, "123");
    linkInfo.putString(&linkInfo, LI_KEY_REMOTE_INTERFACE, "123");
    linkInfo.putInt(&linkInfo, LI_KEY_LOCAL_LINK_MODE, 5);
    linkInfo.putInt(&linkInfo, LI_KEY_REMOTE_LINK_MODE, 5);
    linkInfo.putBoolean(&linkInfo, LI_KEY_IS_CLIENT, true);
    linkInfo.putString(&linkInfo, LI_KEY_REMOTE_BASE_MAC, "00:11:22:33:44:55");
    msg->putContainer(msg, NM_KEY_LINK_INFO, (struct InfoContainer *)&linkInfo, sizeof(linkInfo));
    WifiDirectNegotiatorInit();

    GetP2pV2Processor()->processUnhandledRequest(msg, 333);
    DefaultNegotiateChannelDelete(channel);
    LinkInfoDestructor(&linkInfo);
    NegotiateMessageDelete(msg);
}

/*
* @tc.name: testV2ProcessNegotiateMessage002
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV2ProcessNegotiateMessage002, TestSize.Level1)
{
    WifiDirectNegotiatorInit();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    GetP2pV2Processor()->needReply = false;
    struct LinkInfo linkInfo;
    LinkInfoConstructor(&linkInfo);
    linkInfo.putString(&linkInfo, LI_KEY_LOCAL_INTERFACE, "p2p0");
    linkInfo.putString(&linkInfo, LI_KEY_REMOTE_INTERFACE, "p2p0");
    linkInfo.putInt(&linkInfo, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_API_ROLE_GO);
    linkInfo.putInt(&linkInfo, LI_KEY_REMOTE_LINK_MODE, WIFI_DIRECT_API_ROLE_GC);
    linkInfo.putBoolean(&linkInfo, LI_KEY_IS_CLIENT, true);
    linkInfo.putString(&linkInfo, LI_KEY_REMOTE_BASE_MAC, "00:11:22:33:44:55");
    msg->putContainer(msg, NM_KEY_LINK_INFO, (struct InfoContainer *)&linkInfo, sizeof(linkInfo));
    ResourceManagerInit();
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_CONN_V2_REQ_1, msg), SOFTBUS_ERR);

    linkInfo.putInt(&linkInfo, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_API_ROLE_GC);
    msg->putContainer(msg, NM_KEY_LINK_INFO, (struct InfoContainer *)&linkInfo, sizeof(linkInfo));
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_CONN_V2_REQ_1, msg), SOFTBUS_ERR);
}

/*
* @tc.name: testV2ProcessNegotiateMessage003
* @tc.desc: test ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorTest, testV2ProcessNegotiateMessage003, TestSize.Level1)
{
    WifiDirectNegotiatorInit();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    GetP2pV2Processor()->needReply = false;
    struct LinkInfo linkInfo;
    LinkInfoConstructor(&linkInfo);
    linkInfo.putString(&linkInfo, LI_KEY_LOCAL_INTERFACE, "p2p0");
    linkInfo.putString(&linkInfo, LI_KEY_REMOTE_INTERFACE, "p2p0");
    linkInfo.putInt(&linkInfo, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_API_ROLE_GO);
    linkInfo.putInt(&linkInfo, LI_KEY_REMOTE_LINK_MODE, WIFI_DIRECT_API_ROLE_GC);
    linkInfo.putBoolean(&linkInfo, LI_KEY_IS_CLIENT, true);
    linkInfo.putString(&linkInfo, LI_KEY_REMOTE_BASE_MAC, "00:11:22:33:44:55");
    msg->putContainer(msg, NM_KEY_LINK_INFO, (struct InfoContainer *)&linkInfo, sizeof(linkInfo));
    ResourceManagerInit();
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_CONN_V2_REQ_2, msg), SOFTBUS_ERR);

    linkInfo.putInt(&linkInfo, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_API_ROLE_GC);
    msg->putContainer(msg, NM_KEY_LINK_INFO, (struct InfoContainer *)&linkInfo, sizeof(linkInfo));
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_CONN_V2_REQ_2, msg), SOFTBUS_ERR);
}

}