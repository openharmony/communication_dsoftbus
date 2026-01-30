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

#include "dsoftbus_enhance_interface.h"
#include "g_enhance_lnn_func.h"
#include "lnn_net_ledger.c"
#include "lnn_net_ledger_deps_mock.h"
#include "lnn_node_info_struct.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNNetLedgerMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNNetLedgerMockTest::SetUpTestCase() { }

void LNNNetLedgerMockTest::TearDownTestCase() { }

void LNNNetLedgerMockTest::SetUp() { }

void LNNNetLedgerMockTest::TearDown() { }

/*
 * @tc.name: IsLocalIrkInfoChangeTest001
 * @tc.desc: Verify IsLocalIrkInfoChange returns false when
 *           LnnGetLocalByteInfo returns SOFTBUS_NETWORK_NOT_FOUND
 * @tc.type: FUNC
 * @tc.level: Level0
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalIrkInfoChangeTest001, TestSize.Level0)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    EXPECT_EQ(IsLocalIrkInfoChange(&info), false);
}

/*
 * @tc.name: IsLocalIrkInfoChangeTest002
 * @tc.desc: Verify IsLocalIrkInfoChange returns false when
 *           LnnGetLocalByteInfo returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level0
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalIrkInfoChangeTest002, TestSize.Level0)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(IsLocalIrkInfoChange(&info), false);
}

/*
 * @tc.name: IsLocalBroadcastLinKeyChangeTest001
 * @tc.desc: Verify IsLocalBroadcastLinKeyChange returns false when
 *           LnnGetLocalByteInfo returns SOFTBUS_NETWORK_NOT_FOUND
 * @tc.type: FUNC
 * @tc.level: Level0
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalBroadcastLinKeyChangeTest001, TestSize.Level0)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    EXPECT_EQ(IsLocalBroadcastLinKeyChange(&info), false);
}

/*
 * @tc.name: IsLocalBroadcastLinKeyChangeTest002
 * @tc.desc: Verify IsLocalBroadcastLinKeyChange returns false when
 *           LnnGetLocalByteInfo returns SOFTBUS_OK then SOFTBUS_ERR
 * @tc.type: FUNC
 * @tc.level: Level0
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalBroadcastLinKeyChangeTest002, TestSize.Level0)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_OK)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_EQ(IsLocalBroadcastLinKeyChange(&info), false);
}

/*
 * @tc.name: IsLocalBroadcastLinKeyChangeTest003
 * @tc.desc: Verify IsLocalBroadcastLinKeyChange returns false when
 *           LnnGetLocalByteInfo returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level0
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalBroadcastLinKeyChangeTest003, TestSize.Level0)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(IsLocalBroadcastLinKeyChange(&info), false);
}

/*
 * @tc.name: IsStaticFeatureChangeTest001
 * @tc.desc: Verify IsStaticFeatureChange checks if static feature has
 *           changed with different feature values
 * @tc.type: FUNC
 * @tc.level: Level0
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, IsStaticFeatureChangeTest001, TestSize.Level0)
{
    uint64_t softbusFeature = 1 << BIT_FL_CAPABILITY;
    uint64_t feature = softbusFeature;
    bool ret = IsStaticFeatureChange(softbusFeature, feature);
    EXPECT_FALSE(ret);
    feature |= (1 << BIT_BLE_DIRECT_ONLINE);
    ret = IsStaticFeatureChange(softbusFeature, feature);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: IsLocalSparkCheckChange001
 * @tc.desc: Verify IsLocalSparkCheckChange checks spark check change with
 *           different LnnGetLocalByteInfo return values
 * @tc.type: FUNC
 * @tc.level: Level0
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalSparkCheckChange001, TestSize.Level0)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NiceMock<NetLedgerDepsInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(IsLocalSparkCheckChange(&info), false);
    EXPECT_EQ(IsLocalSparkCheckChange(&info), false);
    info.sparkCheck[0] = 1;
    EXPECT_EQ(IsLocalSparkCheckChange(&info), true);
}

/*
 * @tc.name: IsBleDirectlyOnlineFactorChange001
 * @tc.desc: Verify IsBleDirectlyOnlineFactorChange checks BLE directly
 *           online factor change with different return values
 * @tc.type: FUNC
 * @tc.level: Level0
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsBleDirectlyOnlineFactorChange001, TestSize.Level0)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NiceMock<NetLedgerDepsInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(IsBleDirectlyOnlineFactorChange(&info), false);
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(IsBleDirectlyOnlineFactorChange(&info), false);
    info.sparkCheck[0] = 1;
    EXPECT_EQ(IsBleDirectlyOnlineFactorChange(&info), true);
}
} // namespace OHOS
