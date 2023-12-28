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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_lane_deps_mock.h"
#include "lnn_lane_link.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "lnn_select_rule.h"
#include "lnn_lane_link_deps_mock.h"
#include "lnn_lane_link_p2p.h"
#include "bus_center_manager.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNLaneLinkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneLinkTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkTest start";
}

void LNNLaneLinkTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkTest end";
}

void LNNLaneLinkTest::SetUp()
{
}

void LNNLaneLinkTest::TearDown()
{
}

static void OnLaneLinkSuccess(uint32_t reqId, const LaneLinkInfo *linkInfo)
{
    (void)reqId;
    (void)linkInfo;
    return;
}

static void OnLaneLinkFail(uint32_t reqId, int32_t reason)
{
    (void)reqId;
    (void)reason;
    return;
}

static void OnLaneLinkException(uint32_t reqId, int32_t reason)
{
    (void)reqId;
    (void)reason;
    return;
}

/*
* @tc.name: LNN_LANE_LINK_001
* @tc.desc: LnnConnectP2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_001, TestSize.Level1)
{
    uint32_t laneLinkReqId = 0;
    int32_t ret = LnnConnectP2p(nullptr, laneLinkReqId, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
 
    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
        .OnLaneLinkException = OnLaneLinkException,
    };
    LaneDepsInterfaceMock linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    LinkRequest *request = (LinkRequest *)SoftBusCalloc(sizeof(LinkRequest));
    if (request == NULL) {
        return;
    }
    
    request->pid = 1024;
    request->networkDelegate = false;
    request->p2pOnly = false;
    request->transType = LANE_T_BYTE;
    request->linkType = LANE_BLE;
    request->acceptableProtocols = 0;

    ret = LnnConnectP2p(request, laneLinkReqId, &cb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnConnectP2p(request, laneLinkReqId, &cb);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = LnnConnectP2p(request, laneLinkReqId, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnConnectP2p(request, laneLinkReqId, &cb);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = LnnConnectP2p(request, laneLinkReqId, &cb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnConnectP2p(request, laneLinkReqId, &cb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(request);
}

/*
* @tc.name: LNN_LANE_LINK_002
* @tc.desc: LnnDisconnectP2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_002, TestSize.Level1)
{
    uint32_t laneLinkReqId = 22;
    uint64_t local = 1 << 14;
    uint64_t remote = 1 << 14;
    LinkRequest *request = (LinkRequest *)SoftBusCalloc(sizeof(LinkRequest));
    if (request == NULL) {
       return;
    }
    
    request->pid = 1024;
    request->networkDelegate = true;
    request->p2pOnly = false;
    request->transType = LANE_T_MIX;
    request->linkType = LANE_BR;
    request->acceptableProtocols = 1;
    uint32_t ret = LnnConnectP2p(request, laneLinkReqId, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    
    LaneDepsInterfaceMock linkMock;
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
        .OnLaneLinkException = OnLaneLinkException,
    };

    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(laneLinkMock, GetTransOptionByLaneId).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LnnConnectP2p(request, laneLinkReqId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnConnectP2p(request, laneLinkReqId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnConnectP2p(request, laneLinkReqId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnConnectP2p(request, laneLinkReqId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(request);
}

/*
* @tc.name: LNN_LANE_LINK_003
* @tc.desc: LnnDisconnectP2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_003, TestSize.Level1)
{
    uint32_t laneLinkReqId = 1;
    LinkRequest *request = (LinkRequest *)SoftBusCalloc(sizeof(LinkRequest));
    if (request == NULL) {
       return;
    }
    request->pid = 1024;
    request->networkDelegate = false;
    request->p2pOnly = false;
    request->transType = LANE_T_BYTE;
    request->linkType = LANE_BLE;
    request->acceptableProtocols = 0;

    uint32_t ret = LnnConnectP2p(request, laneLinkReqId, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    
    LaneDepsInterfaceMock linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
        .OnLaneLinkException = OnLaneLinkException,
    };

    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(laneLinkMock, GetTransOptionByLaneId).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LnnConnectP2p(request, laneLinkReqId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(request);
}

/*
* @tc.name: LNN_LANE_LINK_004
* @tc.desc: LnnDisconnectP2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_004, TestSize.Level1)
{
    LinkRequest *request = (LinkRequest *)SoftBusCalloc(sizeof(LinkRequest));
    if (request == NULL) {
       return;
    }

    request->pid = 1024;
    request->networkDelegate = false;
    request->p2pOnly = false;
    request->transType = LANE_T_BYTE;
    request->linkType = LANE_BLE;
    request->acceptableProtocols = 0;

    uint32_t laneLinkReqId = 1;
    uint32_t ret = LnnConnectP2p(request, laneLinkReqId, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    
    LaneDepsInterfaceMock linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
        .OnLaneLinkException = OnLaneLinkException,
    };

    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(laneLinkMock, GetTransOptionByLaneId).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LnnConnectP2p(request, laneLinkReqId, &cb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(request);
}

/*
* @tc.name: LNN_LANE_LINK_005
* @tc.desc: LnnDisconnectP2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_005, TestSize.Level1)
{
    const char *network = "network123";
    int32_t pid = 123;
    uint32_t laneLinkReqId = 2334;
    LnnDisconnectP2p(network, pid, laneLinkReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: LNN_LANE_LINK_006
* @tc.desc: LnnConnectP2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_006, TestSize.Level1)
{
    uint32_t laneLinkReqId = 1;
    const char *network = "network123";
    LaneDepsInterfaceMock linkMock;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(connInfo), 0, sizeof(connInfo));
    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
        .OnLaneLinkException = OnLaneLinkException,
    };
    LinkRequest *request = (LinkRequest *)SoftBusCalloc(sizeof(LinkRequest));
    if (request == NULL) {
       return;
    }

    request->pid = 1024;
    request->networkDelegate = false;
    request->p2pOnly = false;
    request->transType = LANE_T_BYTE;
    request->linkType = LANE_BLE;
    request->acceptableProtocols = 0;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(2), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    
    connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, GetAuthIdByConnInfo).WillRepeatedly(Return(5));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(5));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));

    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(laneLinkMock, GetTransOptionByLaneId).WillRepeatedly(Return(SOFTBUS_OK));

    uint32_t ret = LnnConnectP2p(request, laneLinkReqId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDisconnectP2p(network, request->pid, laneLinkReqId);
    SoftBusFree(request);
}

/*
* @tc.name: GET_WLAN_LINKED_FREQUENCY_TEST_001
* @tc.desc: LnnQueryLaneResource test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GET_WLAN_LINKED_FREQUENCY_TEST_001, TestSize.Level1)
{
    int32_t ret = GetWlanLinkedFrequency();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: GET_WLAN_LINKED_FREQUENCY_TEST_001
* @tc.desc: LnnQueryLaneResource test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GET_WLAN_LINKED_FREQUENCY_TEST_002, TestSize.Level1)
{
    typedef enum {
    TEST_BR = -1,
   } TestLinkType;

    TestLinkType testLink = TEST_BR;
    LaneLinkType linkType = (LaneLinkType)testLink;
    LinkAttribute *ret = GetLinkAttrByLinkType(linkType);
    EXPECT_TRUE(ret == NULL);
    linkType = LANE_LINK_TYPE_BUTT;
    ret = GetLinkAttrByLinkType(linkType);
    EXPECT_TRUE(ret == NULL);
    linkType = LANE_P2P;
    ret = GetLinkAttrByLinkType(linkType);
    EXPECT_TRUE(ret != NULL);
}
} // namespace OHOS