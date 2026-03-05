/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#define MAX_STATE_VERSION 0xFF
constexpr char SOFTBUS_VERSION[MAX_STATE_VERSION] = "softBusVersion";
constexpr uint8_t IRK1[LFINDER_IRK_LEN] = "tmpIrk1";
constexpr uint8_t IRK2[LFINDER_IRK_LEN] = "tmpIrk2";
constexpr uint8_t KEY1[SESSION_KEY_LENGTH] = "tmpKey1";
constexpr uint8_t KEY2[SESSION_KEY_LENGTH] = "tmpKey2";
constexpr uint8_t IV1[BROADCAST_IV_LEN] = "tmpIv1";
constexpr uint8_t IV2[BROADCAST_IV_LEN] = "tmpIv2";
constexpr int32_t TEST_FD = 12;

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
 * @tc.desc: Verify IsLocalIrkInfoChange returns false when LnnGetLocalByteInfo
 *           returns SOFTBUS_NETWORK_NOT_FOUND, indicating no local IRK info is found
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalIrkInfoChangeTest001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    EXPECT_EQ(IsLocalIrkInfoChange(&info), false);
}

/*
 * @tc.name: IsLocalIrkInfoChangeTest002
 * @tc.desc: Verify IsLocalIrkInfoChange returns false when LnnGetLocalByteInfo
 *           returns SOFTBUS_OK with empty IRK info, indicating no change in IRK
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalIrkInfoChangeTest002, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(IsLocalIrkInfoChange(&info), false);
}

/*
 * @tc.name: IsLocalBroadcastLinKeyChangeTest001
 * @tc.desc: Verify IsLocalBroadcastLinKeyChange returns false when LnnGetLocalByteInfo
 *           returns SOFTBUS_NETWORK_NOT_FOUND, indicating no local broadcast key info is found
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalBroadcastLinKeyChangeTest001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    EXPECT_EQ(IsLocalBroadcastLinKeyChange(&info), false);
}

/*
 * @tc.name: IsLocalBroadcastLinKeyChangeTest002
 * @tc.desc: Verify IsLocalBroadcastLinKeyChange returns false when LnnGetLocalByteInfo
 *           returns SOFTBUS_OK for key then SOFTBUS_ERR for IV, indicating partial key info retrieval
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalBroadcastLinKeyChangeTest002, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_OK)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_EQ(IsLocalBroadcastLinKeyChange(&info), false);
}

/*
 * @tc.name: IsLocalBroadcastLinKeyChangeTest003
 * @tc.desc: Verify IsLocalBroadcastLinKeyChange returns false when LnnGetLocalByteInfo
 *           returns SOFTBUS_OK with empty broadcast key info, indicating no change in broadcast key
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalBroadcastLinKeyChangeTest003, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(IsLocalBroadcastLinKeyChange(&info), false);
}

/*
 * @tc.name: LnnInitNetLedgerTest001
 * @tc.desc: Verify LnnInitNetLedger handles various initialization failures and success scenarios,
 *           testing module notify, local ledger, distributed ledger, and meta node ledger initialization
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnInitNetLedgerTest001, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnInitModuleNotifyWithRetrySync)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnInitLocalLedger)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnInitDistributedLedger)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnInitMetaNodeLedger)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnInitNetLedger(), SOFTBUS_HUKS_INIT_FAILED);
    EXPECT_EQ(LnnInitNetLedger(), SOFTBUS_NETWORK_LEDGER_INIT_FAILED);
    EXPECT_EQ(LnnInitNetLedger(), SOFTBUS_NETWORK_LEDGER_INIT_FAILED);
    EXPECT_EQ(LnnInitNetLedger(), SOFTBUS_NETWORK_LEDGER_INIT_FAILED);
    EXPECT_EQ(LnnInitNetLedger(), SOFTBUS_OK);
    EXPECT_EQ(LnnInitNetLedger(), SOFTBUS_OK);
}

/*
 * @tc.name: IsCapacityChangeTest001
 * @tc.desc: Verify IsCapacityChange returns false when all local capacity info
 *           retrieval functions return SOFTBUS_INVALID_PARAM, indicating no valid capacity data
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, IsCapacityChangeTest001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(IsCapacityChange(&info), false);
}

/*
 * @tc.name: IsCapacityChangeTest002
 * @tc.desc: Verify IsCapacityChange correctly detects capacity changes when node info
 *           has different feature, authCapacity, heartbeatCapacity, and staticNetCap values
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, IsCapacityChangeTest002, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.feature = 1;
    info.authCapacity = 2;
    info.heartbeatCapacity = 3;
    info.staticNetCap = 4;
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(IsCapacityChange(&info), true);
    info.feature = 0;
    EXPECT_EQ(IsCapacityChange(&info), true);
    info.authCapacity = 0;
    EXPECT_EQ(IsCapacityChange(&info), true);
    info.heartbeatCapacity = 0;
    EXPECT_EQ(IsCapacityChange(&info), true);
    info.staticNetCap = 0;
    EXPECT_EQ(IsCapacityChange(&info), false);
}

/*
 * @tc.name: IsCapacityChangeTest003
 * @tc.desc: Verify IsCapacityChange handles sleRangeCapacity and tests scenarios
 *           where LnnGetLocalNumInfo returns different values including negative values
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, IsCapacityChangeTest003, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.feature = 0;
    info.authCapacity = 0;
    info.heartbeatCapacity = 0;
    info.staticNetCap = 0;
    info.sleRangeCapacity = 1;
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillRepeatedly(DoAll(SetArgPointee<1>(-1), Return(SOFTBUS_OK)));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(IsCapacityChange(&info), true);

    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(IsCapacityChange(&info), false);
}

/*
 * @tc.name: IsLocalIrkInfoChangeTest003
 * @tc.desc: Verify IsLocalIrkInfoChange returns true when node IRK differs from
 *           local IRK, indicating a change in IRK information that needs to be updated
 * @tc.type: FUNC
 * @tc.level: Level0
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalIrkInfoChangeTest003, TestSize.Level0)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(memcpy_s(info.rpaInfo.peerIrk, LFINDER_IRK_LEN, IRK1, LFINDER_IRK_LEN), EOK);
    unsigned char localIrk[LFINDER_IRK_LEN] = {0};
    EXPECT_EQ(memcpy_s(localIrk, LFINDER_IRK_LEN, IRK2, LFINDER_IRK_LEN), EOK);
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(*localIrk), Return(SOFTBUS_OK)));
    EXPECT_EQ(IsLocalIrkInfoChange(&info), true);
}

/*
 * @tc.name: IsLocalBroadcastLinKeyChangeTest004
 * @tc.desc: Verify IsLocalBroadcastLinKeyChange returns true when node broadcast key
 *           and IV differ from local values, indicating a change in broadcast cipher info
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalBroadcastLinKeyChangeTest004, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(memcpy_s(info.cipherInfo.key, SESSION_KEY_LENGTH, KEY1, SESSION_KEY_LENGTH), EOK);
    EXPECT_EQ(memcpy_s(info.cipherInfo.iv, BROADCAST_IV_LEN, IV1, BROADCAST_IV_LEN), EOK);
    unsigned char key[SESSION_KEY_LENGTH] = {0};
    unsigned char iv[BROADCAST_IV_LEN] = {0};
    EXPECT_EQ(memcpy_s(key, SESSION_KEY_LENGTH, KEY2, SESSION_KEY_LENGTH), EOK);
    EXPECT_EQ(memcpy_s(iv, BROADCAST_IV_LEN, IV2, BROADCAST_IV_LEN), EOK);
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo)
        .WillOnce(DoAll(SetArgPointee<1>(*key), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(*iv), Return(SOFTBUS_OK)));
    EXPECT_EQ(IsLocalBroadcastLinKeyChange(&info), true);
}

/*
 * @tc.name: IsBleDirectlyOnlineFactorChangeTest001
 * @tc.desc: Verify IsBleDirectlyOnlineFactorChange correctly detects changes in BLE
 *           directly online factors including device OS type and security level
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsBleDirectlyOnlineFactorChangeTest001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.deviceInfo.osType = 100;
    info.deviceSecurityLevel = 1;
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalBoolInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(IsBleDirectlyOnlineFactorChange(&info), true);
    info.deviceInfo.osType = 0;
    EXPECT_EQ(IsBleDirectlyOnlineFactorChange(&info), true);
    info.deviceSecurityLevel = 0;
    EXPECT_EQ(IsBleDirectlyOnlineFactorChange(&info), true);
}

bool g_isSupportMcu = false;
bool IsSupportMcuFeatrueTest(void)
{
    return g_isSupportMcu;
}

/*
 * @tc.name: LnnSetLocalFeatureTest001
 * @tc.desc: Verify LnnSetLocalFeature handles MCU feature support and sets local
 *           feature capabilities correctly with different mock return values
 * @tc.level: Level1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnSetLocalFeatureTest001, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnIsSupportLpSparkFeaturePacked).WillRepeatedly(Return(true));
    EXPECT_CALL(netLedgerMock, LnnIsFeatureSupportDetailPacked).WillRepeatedly(Return(true));
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->isSupportMcuFeature = IsSupportMcuFeatrueTest;

    g_isSupportMcu = true;
    EXPECT_NO_FATAL_FAILURE(LnnSetLocalFeature());
    EXPECT_CALL(netLedgerMock, LnnSetLocalNum64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(LnnSetLocalFeature());
    g_isSupportMcu = false;
    EXPECT_NO_FATAL_FAILURE(LnnSetLocalFeature());
}

/*
 * @tc.name: LnnSetLocalFeatureTest002
 * @tc.desc: Verify LnnSetLocalFeature handles LP feature support scenarios and
 *           sets feature capability with different LnnSetLocalByteInfo return values
 * @tc.level: Level1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnSetLocalFeatureTest002, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, IsSupportLpFeaturePacked).WillOnce(Return(true)).WillRepeatedly(Return(false));
    EXPECT_CALL(netLedgerMock, LnnIsSupportLpSparkFeaturePacked).WillOnce(Return(true)).WillRepeatedly(Return(false));
    EXPECT_CALL(netLedgerMock, LnnSetFeatureCapability).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnSetLocalByteInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(LnnSetLocalFeature());
    EXPECT_NO_FATAL_FAILURE(LnnSetLocalFeature());
}

/*
 * @tc.name: ProcessLocalDeviceInfoTest001
 * @tc.desc: Verify ProcessLocalDeviceInfo processes local device info including
 *           network ID, device name updates, and handles various mock return scenarios
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, ProcessLocalDeviceInfoTest001, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalDevInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnDumpNodeInfo).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, LnnDumpNodeInfo).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalBoolInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnSaveLocalDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnUpdateLocalNetworkId)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnUpdateLocalDeviceName)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnNotifyNetworkIdChangeEvent).WillRepeatedly(Return());
    EXPECT_NO_FATAL_FAILURE(ProcessLocalDeviceInfo());
    EXPECT_NO_FATAL_FAILURE(ProcessLocalDeviceInfo());
    EXPECT_NO_FATAL_FAILURE(ProcessLocalDeviceInfo());
    EXPECT_NO_FATAL_FAILURE(ProcessLocalDeviceInfo());

    NodeInfo deviceInfo;
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memcpy_s(deviceInfo.softBusVersion, VERSION_MAX_LEN, SOFTBUS_VERSION, VERSION_MAX_LEN);
    deviceInfo.stateVersion = MAX_STATE_VERSION;
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalDevInfoPacked)
        .WillRepeatedly(DoAll(SetArgPointee<0>(deviceInfo), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(ProcessLocalDeviceInfo());
}

/*
 * @tc.name: LnnInitNetLedgerDelayTest001
 * @tc.desc: Verify LnnInitNetLedgerDelay initializes auth device key, local ledger,
 *           and decision database with delay, handling various initialization failures
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnInitNetLedgerDelayTest001, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, AuthLoadDeviceKey).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, LnnInitLocalLedgerDelay).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnInitNetLedgerDelay(), SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(netLedgerMock, LnnInitDecisionDbDelay).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnInitNetLedgerDelay(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnInitNetLedgerDelay(), SOFTBUS_OK);
}

/*
 * @tc.name: LnnInitEventMoniterDelayTest001
 * @tc.desc: Verify LnnInitEventMoniterDelay initializes common event monitor
 *           with delay, handling initialization failure and success scenarios
 * @tc.level: Level1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnInitEventMoniterDelayTest001, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnInitCommonEventMonitorImpl).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnInitEventMoniterDelay(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnInitEventMoniterDelay(), SOFTBUS_OK);
}

/*
 * @tc.name: LnnGetNodeKeyInfoLocalTest001
 * @tc.desc: Verify LnnGetNodeKeyInfoLocal returns SOFTBUS_INVALID_PARAM when
 *           networkId is nullptr or info buffer is nullptr, validating input parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnGetNodeKeyInfoLocalTest001, TestSize.Level1)
{
    const char *networkId = "networkId";
    uint8_t info;
    EXPECT_EQ(LnnGetNodeKeyInfoLocal(nullptr, 1, &info, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetNodeKeyInfoLocal(networkId, 1, nullptr, 2), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetNodeKeyInfoRemoteTest001
 * * @tc.desc: Verify LnnGetNodeKeyInfoRemote handles null parameters and retrieves
 *           remote node key info for various key types including P2P IP, security level,
 *           screen status, and static network capability
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnGetNodeKeyInfoRemoteTest001, TestSize.Level1)
{
    const char *networkId = "networkId";
    uint8_t info;
    EXPECT_EQ(LnnGetNodeKeyInfoRemote(nullptr, 1, &info, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetNodeKeyInfoRemote(networkId, 1, nullptr, 2), SOFTBUS_INVALID_PARAM);
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetRemoteBoolInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnGetNodeKeyInfoRemote(networkId, NODE_KEY_P2P_IP_ADDRESS, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetNodeKeyInfoRemote(networkId, NODE_KEY_DEVICE_SECURITY_LEVEL, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetNodeKeyInfoRemote(networkId, NODE_KEY_DEVICE_SCREEN_STATUS, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetNodeKeyInfoRemote(networkId, NODE_KEY_STATIC_NETWORK_CAP, &info, 2), SOFTBUS_OK);
}

/*
 * @tc.name: LnnGetNodeKeyInfoTest001
 * @tc.desc: Verify LnnGetNodeKeyInfo returns appropriate error codes for null
 *           parameters and when local node info retrieval fails
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnGetNodeKeyInfoTest001, TestSize.Level1)
{
    const char *networkId = "networkId";
    uint8_t info;
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(LnnGetNodeKeyInfo(nullptr, NODE_KEY_P2P_IP_ADDRESS, &info, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetNodeKeyInfo(networkId, NODE_KEY_P2P_IP_ADDRESS, nullptr, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetNodeKeyInfo(networkId, NODE_KEY_P2P_IP_ADDRESS, &info, 2),
        SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);
}

/*
 * @tc.name: LnnGetPrivateNodeKeyInfoLocalTest001
 * @tc.desc: Verify LnnGetPrivateNodeKeyInfoLocal returns SOFTBUS_INVALID_PARAM for
 *           null parameters and unsupported key types like BYTE_KEY_STATIC_CAPABILITY
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnGetPrivateNodeKeyInfoLocalTest001, TestSize.Level1)
{
    const char *networkId = "networkId";
    uint8_t info;
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoLocal(nullptr, BYTE_KEY_IRK, &info, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoLocal(networkId, BYTE_KEY_IRK, nullptr, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoLocal(networkId, BYTE_KEY_STATIC_CAPABILITY, &info, 2), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetPrivateNodeKeyInfoRemoteTest001
 * @tc.desc: Verify LnnGetPrivateNodeKeyInfoRemote retrieves private node key info
 *           for various key types including IRK, broadcast cipher key, account hash,
 *           and remote PTK, handling null parameters appropriately
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnGetPrivateNodeKeyInfoRemoteTest001, TestSize.Level1)
{
    const char *networkId = "networkId";
    uint8_t info;
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(nullptr, BYTE_KEY_IRK, &info, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(networkId, BYTE_KEY_IRK, nullptr, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(networkId, BYTE_KEY_IRK, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(networkId, BYTE_KEY_BROADCAST_CIPHER_KEY, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(networkId, BYTE_KEY_ACCOUNT_HASH, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(networkId, BYTE_KEY_REMOTE_PTK, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(networkId, BYTE_KEY_STATIC_CAPABILITY, &info, 2), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetPrivateNodeKeyInfoTest001
 * @tc.desc: Verify LnnGetPrivateNodeKeyInfo handles null parameters, distinguishes
 *           between local and remote node info, and retrieves private node key info correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnGetPrivateNodeKeyInfoTest001, TestSize.Level1)
{
    const char *networkId = "networkId";
    const char *networkIdNew = "networkIdNew";
    uint8_t info;
    char localNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    EXPECT_EQ(strcpy_s(localNetworkId, NETWORK_ID_BUF_LEN, networkIdNew), EOK);
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<1>(*localNetworkId), Return(SOFTBUS_OK)));
    EXPECT_EQ(LnnGetPrivateNodeKeyInfo(nullptr, BYTE_KEY_REMOTE_PTK, &info, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfo(networkId, BYTE_KEY_REMOTE_PTK, nullptr, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfo(networkId, BYTE_KEY_REMOTE_PTK, &info, 2), SOFTBUS_NOT_FIND);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfo(networkId, BYTE_KEY_REMOTE_PTK, &info, 2), SOFTBUS_OK);
}

/*
 * @tc.name: LnnSetDataLevelTest001
 * @tc.desc: Verify LnnSetDataLevel validates input parameters, sets data level,
 *           and handles various error scenarios from ledger info operations
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnSetDataLevelTest001, TestSize.Level1)
{
    DataLevel dataLevel;
    (void)memset_s(&dataLevel, sizeof(DataLevel), 0, sizeof(DataLevel));
    bool isSwitchLevelChanged = false;
    EXPECT_EQ(LnnSetDataLevel(nullptr, &isSwitchLevelChanged), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnSetDataLevel(&dataLevel, nullptr), SOFTBUS_INVALID_PARAM);
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU16Info).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(LnnSetDataLevel(&dataLevel, &isSwitchLevelChanged), SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR);
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU16Info).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(LnnSetDataLevel(&dataLevel, &isSwitchLevelChanged), SOFTBUS_NETWORK_GET_LEDGER_INFO_ERR);
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU16Info).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU32Info).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(LnnSetDataLevel(&dataLevel, &isSwitchLevelChanged), SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR);
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU16Info).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnSetDataLevel(&dataLevel, &isSwitchLevelChanged), SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR);
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU16Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnSetDataLevel(&dataLevel, &isSwitchLevelChanged), SOFTBUS_OK);
}

/*
 * @tc.name: SoftbusDumpPrintAccountIdTest001
 * @tc.desc: Verify various dump print functions handle null node info and
 *           return appropriate error codes for UDID, UUID, MAC, IP, network capability,
 *           device level, screen status, IRK, broadcast cipher, and remote PTK
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, SoftbusDumpPrintAccountIdTest001, TestSize.Level1)
{
    NodeBasicInfo nodeInfo;
    int32_t fd = TEST_FD;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(SoftbusDumpPrintUdid(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintUdid(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintUuid(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintUuid(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintMac(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintMac(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintIp(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintIp(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintDynamicNetCap(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintNetType(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintDeviceLevel(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintDeviceLevel(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintScreenStatus(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintScreenStatus(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintStaticNetCap(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintStaticNetCap(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintIrk(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintIrk(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintBroadcastCipher(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintBroadcastCipher(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintRemotePtk(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintRemotePtk(fd, &nodeInfo), SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: SoftbusDumpPrintLocalPtkTest001
 * @tc.desc: Verify SoftbusDumpPrintLocalPtk handles null node info, retrieves
 *           local PTK by UUID, and handles byte conversion failures
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, SoftbusDumpPrintLocalPtkTest001, TestSize.Level1)
{
    NodeBasicInfo nodeInfo;
    int32_t fd = TEST_FD;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnAnonymizeDeviceStr).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalPtkByUuid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(SoftbusDumpPrintLocalPtk(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintLocalPtk(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_CALL(netLedgerMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(SoftbusDumpPrintLocalPtk(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_CALL(netLedgerMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(SoftbusDumpPrintLocalPtk(fd, &nodeInfo), SOFTBUS_BYTE_CONVERT_FAIL);
    EXPECT_EQ(SoftbusDumpPrintLocalPtk(fd, &nodeInfo), SOFTBUS_OK);
}

/*
 * @tc.name: SoftbusDumpDeviceInfoTest001
 * @tc.desc: Verify SoftbusDumpDeviceInfo handles null node info and
 *           dumps device information to file descriptor
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, SoftbusDumpDeviceInfoTest001, TestSize.Level1)
{
    NodeBasicInfo nodeInfo;
    int32_t fd = 0;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceInfo(fd, &nodeInfo));
    fd = TEST_FD;
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceInfo(fd, nullptr));
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceInfo(fd, &nodeInfo));
}

/*
 * @tc.name: SoftbusDumpDeviceAddrTest001
 * @tc.desc: Verify SoftbusDumpDeviceAddr handles null node info and
 *           dumps device address information to file descriptor
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, SoftbusDumpDeviceAddrTest001, TestSize.Level1)
{
    NodeBasicInfo nodeInfo;
    int32_t fd = 0;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceAddr(fd, &nodeInfo));
    fd = TEST_FD;
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceAddr(fd, nullptr));
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceAddr(fd, &nodeInfo));
}

/*
 * @tc.name: SoftbusDumpDeviceCipherTest001
 * @tc.desc: Verify SoftbusDumpDeviceCipher handles null node info and
 *           dumps device cipher information to file descriptor
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, SoftbusDumpDeviceCipherTest001, TestSize.Level1)
{
    NodeBasicInfo nodeInfo;
    int32_t fd = 0;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceCipher(fd, &nodeInfo));
    fd = TEST_FD;
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceCipher(fd, nullptr));
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceCipher(fd, &nodeInfo));
}

/*
 * @tc.name: LnnUpdateLocalDeviceInfoTest001
 * @tc.desc: Verify LnnUpdateLocalDeviceInfo clears device info, updates local UUID
 *           and IRK, generates network ID, and handles various initialization failures
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnUpdateLocalDeviceInfoTest001, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, ClearDeviceInfo).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, AuthClearDeviceKey).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, LnnClearPtkList).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, LnnUpdateLocalUuidAndIrk).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnRemoveDb).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, InitTrustedDevInfoTable).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGenBroadcastCipherInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(netLedgerMock, LnnGenLocalNetworkId).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(netLedgerMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_OK);
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_OK);
}

/*
 * @tc.name: IsLocalSparkCheckChange001
 * @tc.desc: Verify IsLocalSparkCheckChange checks spark check change with different
 *           LnnGetLocalByteInfo return values and detects when spark check value changes
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalSparkCheckChange001, TestSize.Level1)
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
 * @tc.desc: Verify IsBleDirectlyOnlineFactorChange checks BLE directly online factor
 *           change with different return values and detects when spark check value changes
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsBleDirectlyOnlineFactorChange001, TestSize.Level1)
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
