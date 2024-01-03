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
#include "default_negotiate_channel_mock.h"
#include "wifi_direct_negotiator_mock.h"
#include "wifi_direct_p2p_adapter_mock.h"
#include "softbus_errcode.h"
#include "wifi_direct_p2p_adapter.h"
#include "resource_manager.h"
#include "negotiate_message.h"
#include "softbus_conn_manager.h"
#include "softbus_feature_config.h"
#include "link_info.h"

using namespace testing::ext;
using testing::Return;
namespace OHOS {
class WifiProcessorV2MockTest : public testing::Test {
public:
    WifiProcessorV2MockTest()
    {}
    ~WifiProcessorV2MockTest()
    {}
    static void SetUpTestCaseForMock() {}
    static void TearDownTestCaseForMock() {}
    void SetUp() override {}
    void TearDown() override {}
};

void SetUpTestCaseForMock(void)
{
    SoftbusConfigInit();
    ConnServerInit();
}

/*
* @tc.name: testV2CreateLink01
* @tc.desc: test V2CreateLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV2MockTest, testV2CreateLink01, TestSize.Level1)
{
    struct WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(connectInfo), 0, sizeof(connectInfo));
    connectInfo.requestId = 2;
    connectInfo.pid = 3;
    connectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    connectInfo.expectApiRole = WIFI_DIRECT_ROLE_GO;
    const char str[] = "00:1A:2B:3C:4D:56";
    strcpy_s(connectInfo.remoteMac, sizeof(connectInfo.remoteMac), str);
    connectInfo.isNetworkDelegate = true;
    connectInfo.linkId = 4;
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, 11111111);
    connectInfo.negoChannel = (struct WifiDirectNegotiateChannel *)&channel;
    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    WifiDirectNegotiatorMock WifiDirectNegotiateMock;
    EXPECT_CALL(WifiDirectNegotiateMock, HandleMessageFromProcessor).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetSelfWifiConfigInfoV2).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(GetP2pV2Processor()->createLink(&connectInfo), SOFTBUS_OK);
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsThreeVapConflict).WillRepeatedly(Return(true));
    EXPECT_EQ(GetP2pV2Processor()->createLink(&connectInfo), ERROR_LOCAL_THREE_VAP_CONFLICT);
}

/*
* @tc.name: testV2ProcessNegotiateMessage001
* @tc.desc: test V2ProcessNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiProcessorV2MockTest, testV2ProcessNegotiateMessage001, TestSize.Level1)
{
    WifiDirectP2pAdapterMock wifiDirectP2pAdapterMock;
    struct NegotiateMessage *msg = NegotiateMessageNew();
    struct LinkInfo *linkInfo = LinkInfoNew();
   
    linkInfo->putString(linkInfo, LI_KEY_LOCAL_INTERFACE, "123");
    linkInfo->putString(linkInfo, LI_KEY_REMOTE_INTERFACE, "123");
    linkInfo->putInt(linkInfo, LI_KEY_LOCAL_LINK_MODE, WIFI_DIRECT_API_ROLE_GO);
    linkInfo->putInt(linkInfo, LI_KEY_REMOTE_LINK_MODE, WIFI_DIRECT_API_ROLE_GC);
    linkInfo->putBoolean(linkInfo, LI_KEY_IS_CLIENT, true);
    linkInfo->putString(linkInfo, LI_KEY_REMOTE_BASE_MAC, "00:11:22:33:44:55");
    msg->putContainer(msg, NM_KEY_LINK_INFO, (struct InfoContainer *)linkInfo, sizeof(*linkInfo));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetInterfaceCoexistCap).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetMacAddress).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(wifiDirectP2pAdapterMock, GetChannel5GListIntArray).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsWifiP2pEnabled).WillRepeatedly(Return(true));
    ResourceManagerInit();
 
    EXPECT_CALL(wifiDirectP2pAdapterMock, IsThreeVapConflict).WillRepeatedly(Return(true));
    EXPECT_EQ(GetP2pV2Processor()->processNegotiateMessage(CMD_CONN_V2_REQ_1, msg), SOFTBUS_ERR);
    LinkInfoDelete(linkInfo);

}

}