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

#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_builder.h"
#include "lnn_net_builder.c"
#include "lnn_net_builder_deps_mock.h"
#include "lnn_node_info.h"
#include "lnn_trans_mock.h"
#include "message_handler.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
class LnnNetBuilderMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnNetBuilderMockTest::SetUpTestCase()
{
    LooperInit();
    NiceMock<LnnTransInterfaceMock> transMock;
    EXPECT_CALL(transMock, TransRegisterNetworkingChannelListener).WillRepeatedly(
        LnnTransInterfaceMock::ActionOfTransRegister);
    int32_t ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void LnnNetBuilderMockTest::TearDownTestCase()
{
    LnnDeinitNetBuilder();
    LooperDeinit();
}

void LnnNetBuilderMockTest::SetUp()
{
}

void LnnNetBuilderMockTest::TearDown()
{
}

/*
* @tc.name: META_AUTH_META_VERIFY_TEST_001
* @tc.desc: test OnAuthMetaVerifyPassed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetBuilderMockTest, META_AUTH_META_VERIFY_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    int64_t authMetaId = 1;
    NodeInfo info;
    OnAuthMetaVerifyPassed(requestId, authMetaId, &info);
}

/*
* @tc.name: META_AUTH_META_VERIFY_TEST_002
* @tc.desc: test OnAuthMetaVerifyPassed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetBuilderMockTest, META_AUTH_META_VERIFY_TEST_002, TestSize.Level1)
{
    uint32_t requestId = 1;
    int64_t authMetaId = 1;
    NodeInfo info;
    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_BR;
    MetaJoinRequestNode *node = TryJoinRequestMetaNode(&addr, true);
    EXPECT_TRUE(node != nullptr);
    OnAuthMetaVerifyPassed(requestId, authMetaId, &info);
}

/*
* @tc.name: LNN_FILL_NODE_INFO_TEST_001
* @tc.desc: test FillNodeInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetBuilderMockTest, LNN_FILL_NODE_INFO_TEST_001, TestSize.Level1)
{
    NetBuilderDepsInterfaceMock uuidMock;
    EXPECT_CALL(uuidMock, AuthGetDeviceUuid(_,_,_)).WillRepeatedly(Return(SOFTBUS_OK));
    MetaJoinRequestNode metaNode;
    NodeInfo info;
    info.uuid[0] = 'x';
    metaNode.addr.type = CONNECTION_ADDR_ETH;
    int32_t ret = FillNodeInfo(&metaNode, &info);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(uuidMock, AuthGetDeviceUuid(_,_,_)).WillRepeatedly(Return(SOFTBUS_OK));
    metaNode.addr.type = CONNECTION_ADDR_WLAN;
    ret = FillNodeInfo(&metaNode, &info);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(uuidMock, AuthGetDeviceUuid(_,_,_)).WillRepeatedly(Return(SOFTBUS_OK));
    metaNode.addr.type = CONNECTION_ADDR_BR;
    ret = FillNodeInfo(&metaNode, &info);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_LEAVE_META_NODE_TEST_001
* @tc.desc: test ProcessLeaveMetaNodeRequest
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetBuilderMockTest, LNN_LEAVE_META_NODE_TEST_001, TestSize.Level1)
{
    int32_t ret = ProcessLeaveMetaNodeRequest(nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_BR;
    MetaJoinRequestNode *node = TryJoinRequestMetaNode(&addr, true);
    EXPECT_TRUE(node != nullptr);
    char *networkId = (char *)SoftBusCalloc(10);
    networkId[0] = 'x';
    ret = ProcessLeaveMetaNodeRequest(networkId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
* @tc.name: LNN_LEAVE_META_TO_LEDGER_TEST_001
* @tc.desc: test LeaveMetaInfoToLedger
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetBuilderMockTest, LNN_LEAVE_META_TO_LEDGER_TEST_001, TestSize.Level1)
{
    NetBuilderDepsInterfaceMock netLedgerMock;
    MetaJoinRequestNode metaInfo;
    LeaveMetaInfoToLedger(&metaInfo, nullptr);

    EXPECT_CALL(netLedgerMock, LnnDeleteMetaInfo(_,_)).WillRepeatedly(Return(SOFTBUS_OK));
    LeaveMetaInfoToLedger(&metaInfo, nullptr);

    EXPECT_CALL(netLedgerMock, LnnDeleteMetaInfo(_,_)).WillRepeatedly(Return(SOFTBUS_ERR));
    LeaveMetaInfoToLedger(&metaInfo, nullptr);
}

/*
* @tc.name: LNN_JOIN_META_NODE_TEST_002
* @tc.desc: test PostJoinRequestToMetaNode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetBuilderMockTest, LNN_JOIN_META_NODE_TEST_002, TestSize.Level1)
{
    MetaJoinRequestNode metaJoinNode;
    int32_t ret = PostJoinRequestToMetaNode(&metaJoinNode, nullptr, nullptr, true);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    CustomData customData;
    metaJoinNode.addr.type = CONNECTION_ADDR_SESSION;
    NiceMock<NetBuilderDepsInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetConnByChanId(_,_,_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthMetaStartVerify(_,_,_,_,_)).WillRepeatedly(Return(SOFTBUS_OK));
    ret = PostJoinRequestToMetaNode(&metaJoinNode, nullptr, &customData, true);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(mock, TransGetConnByChanId(_,_,_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthMetaStartVerify(_,_,_,_,_)).WillRepeatedly(Return(SOFTBUS_OK));
    ret = PostJoinRequestToMetaNode(&metaJoinNode, nullptr, &customData, false);
}
} // namespace OHOS
